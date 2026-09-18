using System;
using System.Security.Cryptography;
using System.Collections.Specialized;
using System.Text;
using System.Net;
using System.IO;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.Diagnostics;
using System.Security.Principal;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Net.Security;
using System.Threading;
using Cryptographic;
using System.Runtime.InteropServices;

namespace EpicAuth
{
    public class api
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool TerminateProcess(IntPtr hProcess, uint uExitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr GetCurrentProcess();

        // Import the required Atom Table functions from kernel32.dll
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern ushort GlobalAddAtom(string lpString);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern ushort GlobalFindAtom(string lpString);

        public string name, ownerid, version, path, seed;
        /// <summary>
        /// Set up your application credentials in order to use EpicAuth
        /// </summary>
        /// <param name="name">Application Name</param>
        /// <param name="ownerid">Your OwnerID, found in your account settings.</param>
        /// <param name="version">Application Version, if version doesnt match it will open the download link you set up in your application settings and close the app, if empty the app will close</param>
        public api(string name, string ownerid, string version, string path = null)
        {
            if (ownerid.Length != 10)
            {
                error("Application not setup correctly. Please watch the YouTube video for setup.");
                TerminateProcess(GetCurrentProcess(), 1);
            }

            this.name = name;

            this.ownerid = ownerid;

            this.version = version;

            this.path = path;
        }

        #region structures
        [DataContract]
        private class EpicResponse
        {
            [DataMember]
            public bool success { get; set; }

            [DataMember]
            public bool newSession { get; set; }

            [DataMember]
            public string sessionid { get; set; }

            [DataMember]
            public string contents { get; set; }

            [DataMember]
            public string response { get; set; }

            [DataMember]
            public string message { get; set; }

            [DataMember]
            public string ownerid { get; set; }

            [DataMember]
            public string download { get; set; }

            [DataMember(IsRequired = false, EmitDefaultValue = false)]
            public EpicUserData info { get; set; }

            [DataMember(IsRequired = false, EmitDefaultValue = false)]
            public EpicAppData appinfo { get; set; }

            [DataMember]
            public List<msg> messages { get; set; }

            [DataMember]
            public List<users> users { get; set; }

            [DataMember(Name = "2fa", IsRequired = false, EmitDefaultValue = false)] // Ensure mapping to "2fa"
            public TwoFactorData twoFactor { get; set; } // Add a property for the 2FA data
        }

        public class msg
        {
            public string message { get; set; }
            public string author { get; set; }
            public string timestamp { get; set; }
        }

        public class users
        {
            public string credential { get; set; }
        }

        [DataContract]
        private class EpicUserData
        {
            [DataMember]
            public string username { get; set; }

            [DataMember]
            public string ip { get; set; }
            [DataMember]
            public string hwid { get; set; }
            [DataMember]
            public string createdate { get; set; }
            [DataMember]
            public string lastlogin { get; set; }
            [DataMember]
            public List<Data> subscriptions { get; set; } // array of subscriptions (basically multiple user ranks for user with individual expiry dates
        }

        [DataContract]
        private class EpicAppData
        {
            [DataMember]
            public string numUsers { get; set; }
            [DataMember]
            public string numOnlineUsers { get; set; }
            [DataMember]
            public string numKeys { get; set; }
            [DataMember]
            public string version { get; set; }
            [DataMember]
            public string customerPanelLink { get; set; }
            [DataMember]
            public string downloadLink { get; set; }
        }
        #endregion
        private static string sessionid, enckey;
        bool initialized;
        /// <summary>
        /// Initializes the connection with EpicAuth in order to use any of the functions
        /// </summary>
        public void Initialize()
        {
            Random rng = new Random();
            const int minSeedLength = 5;
            const int maxSeedLength = 50;
            int seedLength = rng.Next(minSeedLength, maxSeedLength + 1);

            StringBuilder seedBuilder = new StringBuilder(seedLength);
            const int asciiStart = 32;
            const int asciiEnd = 127;

            for (int index = 0; index < seedLength; index++)
            {
                int charCode = rng.Next(asciiStart, asciiEnd);
                seedBuilder.Append((char)charCode);
            }

            seed = seedBuilder.ToString();
            checkAtom();

            NameValueCollection requestParameters = new NameValueCollection
            {
                ["type"] = "init",
                ["ver"] = version,
                ["hash"] = checksum(Process.GetCurrentProcess().MainModule.FileName),
                ["name"] = name,
                ["ownerid"] = ownerid
            };

            bool hasTokenPath = !string.IsNullOrWhiteSpace(path);
            if (hasTokenPath)
            {
                string tokenContent = File.ReadAllText(path);
                string tokenHashValue = TokenHash(path);
                requestParameters.Add("token", tokenContent);
                requestParameters.Add("thash", tokenHashValue);
            }

            string serverResponse = req(requestParameters);

            const string invalidApplicationResponse = "EpicAuth_Invalid";
            if (serverResponse == invalidApplicationResponse)
            {
                error("Application not found");
                TerminateProcess(GetCurrentProcess(), 1);
                return;
            }

            EpicResponse parsedResponse = response_decoder.string_to_generic<EpicResponse>(serverResponse);
            bool isOwnerIdValid = parsedResponse.ownerid == ownerid;

            if (isOwnerIdValid)
            {
                load_response_struct(parsedResponse);

                if (parsedResponse.success)
                {
                    sessionid = parsedResponse.sessionid;
                    initialized = true;
                }
                else if (parsedResponse.message == "invalidver")
                {
                    app_data.downloadLink = parsedResponse.download;
                }
            }
            else
            {
                TerminateProcess(GetCurrentProcess(), 1);
            }
        }

        void checkAtom()
        {
            Thread atomCheckThread = new Thread(() =>
            {
                while (true)
                {
                    Thread.Sleep(60000); // give people 1 minute to login

                    ushort foundAtom = GlobalFindAtom(seed);
                    if (foundAtom == 0)
                    {
                        TerminateProcess(GetCurrentProcess(), 1);
                    }
                }
            });

            atomCheckThread.IsBackground = true; // Ensure the thread does not block program exit
            atomCheckThread.Start();
        }

        public static string TokenHash(string tokenPath)
        {
            using (var sha256 = SHA256.Create())
            {
                using (var s = File.OpenRead(tokenPath))
                {
                    byte[] bytes = sha256.ComputeHash(s);
                    return BitConverter.ToString(bytes).Replace("-", string.Empty);
                }
            }
        }
        /// <summary>
        /// Checks if EpicAuth is been Initalized
        /// </summary>
        public void CheckInit()
        {
            if (!initialized)
            {
                error("You must run the function EpicAuthApp.init(); first");
                TerminateProcess(GetCurrentProcess(), 1);
            }
        }

        /// <summary>
        /// Converts Unix time to Days,Months,Hours
        ///</summary>
        /// <param name="subscription">Subscription Number</param>
        /// <param name="Type">You can choose between Days,Hours,Months </param>
        public string expirydaysleft(string Type, int subscription)
        {
            CheckInit();

            System.DateTime dtDateTime = new DateTime(1970, 1, 1, 0, 0, 0, 0, System.DateTimeKind.Local);
            dtDateTime = dtDateTime.AddSeconds(long.Parse(user_data.subscriptions[subscription].expiry)).ToLocalTime();
            TimeSpan difference = dtDateTime - DateTime.Now;
            switch (Type.ToLower())
            {
                case "months":
                    return Convert.ToString(difference.Days / 30);
                case "days":
                    return Convert.ToString(difference.Days);
                case "hours":
                    return Convert.ToString(difference.Hours);
            }
            return null;

        }

        /// <summary>
        /// Registers the user using a license and gives the user a subscription that matches their license level
        /// </summary>
        /// <param name="username">Username</param>
        /// <param name="pass">Password</param>
        /// <param name="key">License key</param>
        public void register(string username, string pass, string key, string email = "")
        {
            CheckInit();

            string hwid = WindowsIdentity.GetCurrent().User.Value;

            NameValueCollection requestParameters = new NameValueCollection
            {
                ["type"] = "register",
                ["username"] = username,
                ["pass"] = pass,
                ["key"] = key,
                ["email"] = email,
                ["hwid"] = hwid,
                ["sessionid"] = sessionid,
                ["name"] = name,
                ["ownerid"] = ownerid
            };
            string serverResponse = req(requestParameters);

            EpicResponse parsedResponse = response_decoder.string_to_generic<EpicResponse>(serverResponse);
            bool isOwnerIdValid = parsedResponse.ownerid == ownerid;

            if (isOwnerIdValid)
            {
                GlobalAddAtom(seed);
                GlobalAddAtom(ownerid);

                load_response_struct(parsedResponse);
                if (parsedResponse.success)
                { load_user_data(parsedResponse.info); }
                else if (parsedResponse.message == "invalidver")
                {
                    app_data.downloadLink = parsedResponse.download;
                }
            }
            else
            {
                TerminateProcess(GetCurrentProcess(), 1);
            }
        }
        /// <summary>
        /// Allow users to enter their account information and recieve an email to reset their password.
        /// </summary>
        /// <param name="username">Username</param>
        /// <param name="email">Email address</param>
        public void forgot(string username, string email)
        {
            CheckInit();

            NameValueCollection requestParameters = new NameValueCollection
            {
                ["type"] = "forgot",
                ["username"] = username,
                ["email"] = email,
                ["sessionid"] = sessionid,
                ["name"] = name,
                ["ownerid"] = ownerid
            };

            string serverResponse = req(requestParameters);

            EpicResponse parsedResponse = response_decoder.string_to_generic<EpicResponse>(serverResponse);

            load_response_struct(parsedResponse);
        }
        /// <summary>
        /// Authenticates the user using their username and password
        /// </summary>
        /// <param name="username">Username</param>
        /// <param name="pass">Password</param>
        public void login(string username, string pass, string code = null)
        {
            CheckInit();

            string hwid = WindowsIdentity.GetCurrent().User.Value;

            NameValueCollection requestParameters = new NameValueCollection
            {
                ["type"] = "login",
                ["username"] = username,
                ["pass"] = pass,
                ["hwid"] = hwid,
                ["sessionid"] = sessionid,
                ["name"] = name,
                ["ownerid"] = ownerid,
                ["code"] = code ?? string.Empty
            };

            string serverResponse = req(requestParameters);

            EpicResponse parsedResponse = response_decoder.string_to_generic<EpicResponse>(serverResponse);
            bool isOwnerIdValid = parsedResponse.ownerid == ownerid;

            if (isOwnerIdValid)
            {
                GlobalAddAtom(seed);
                GlobalAddAtom(ownerid);

                load_response_struct(parsedResponse);
                if (parsedResponse.success)
                { load_user_data(parsedResponse.info); }
                else if (parsedResponse.message == "invalidver")
                {
                    app_data.downloadLink = parsedResponse.download;
                }
            }
            else
            {
                TerminateProcess(GetCurrentProcess(), 1);
            }
        }

        public void logout()
        {
            CheckInit();

            NameValueCollection requestParameters = new NameValueCollection
            {
                ["type"] = "logout",
                ["sessionid"] = sessionid,
                ["name"] = name,
                ["ownerid"] = ownerid
            };

            string serverResponse = req(requestParameters);

            EpicResponse parsedResponse = response_decoder.string_to_generic<EpicResponse>(serverResponse);
            bool isOwnerIdValid = parsedResponse.ownerid == ownerid;
            if (isOwnerIdValid)
            {
                load_response_struct(parsedResponse);
            }
            else
            {
                TerminateProcess(GetCurrentProcess(), 1);
            }
        }

        public void web_login()
        {
            CheckInit();

            string hwid = WindowsIdentity.GetCurrent().User.Value;

            string datastore, datastore2, outputten;

        start:

            HttpListener listener = new HttpListener();

            outputten = "handshake";
            outputten = "http://localhost:1337/" + outputten + "/";

            listener.Prefixes.Add(outputten);

            listener.Start();

            HttpListenerContext context = listener.GetContext();
            HttpListenerRequest request = context.Request;
            HttpListenerResponse responsepp = context.Response;

            responsepp.AddHeader("Access-Control-Allow-Methods", "GET, POST");
            responsepp.AddHeader("Access-Control-Allow-Origin", "*");
            responsepp.AddHeader("Via", "hugzho's big brain");
            responsepp.AddHeader("Location", "your kernel ;)");
            responsepp.AddHeader("Retry-After", "never lmao");
            responsepp.Headers.Add("Server", "\r\n\r\n");

            if (request.HttpMethod == "OPTIONS")
            {
                responsepp.StatusCode = (int)HttpStatusCode.OK;
                Thread.Sleep(1); // without this, the response doesn't return to the website, and the web buttons can't be shown
                listener.Stop();
                goto start;
            }

            listener.AuthenticationSchemes = AuthenticationSchemes.Negotiate;
            listener.UnsafeConnectionNtlmAuthentication = true;
            listener.IgnoreWriteExceptions = true;

            string data = request.RawUrl;

            datastore2 = data.Replace("/handshake?user=", "");
            datastore2 = datastore2.Replace("&token=", " ");

            datastore = datastore2;

            string user = datastore.Split()[0];
            string token = datastore.Split(' ')[1];

            NameValueCollection requestParameters = new NameValueCollection
            {
                ["type"] = "login",
                ["username"] = user,
                ["token"] = token,
                ["hwid"] = hwid,
                ["sessionid"] = sessionid,
                ["name"] = name,
                ["ownerid"] = ownerid
            };

            string serverResponse = req(requestParameters);

            EpicResponse parsedResponse = response_decoder.string_to_generic<EpicResponse>(serverResponse);
            bool success = true;
            bool isOwnerIdValid = parsedResponse.ownerid == ownerid;

            if (isOwnerIdValid)
            {
                GlobalAddAtom(seed);
                GlobalAddAtom(ownerid);

                load_response_struct(parsedResponse);

                if (parsedResponse.success)
                {
                    load_user_data(parsedResponse.info);

                    responsepp.StatusCode = 420;
                    responsepp.StatusDescription = "SHEESH";
                }
                else
                {
                    Console.WriteLine(parsedResponse.message);
                    responsepp.StatusCode = (int)HttpStatusCode.OK;
                    responsepp.StatusDescription = parsedResponse.message;
                    success = false;
                }
            }
            else
            {
                TerminateProcess(GetCurrentProcess(), 1);
            }

            byte[] buffer = Encoding.UTF8.GetBytes("Complete");

            responsepp.ContentLength64 = buffer.Length;
            Stream output = responsepp.OutputStream;
            output.Write(buffer, 0, buffer.Length);
            Thread.Sleep(1); // without this, the response doesn't return to the website, and the web buttons can't be shown
            listener.Stop();

            if (!success)
                TerminateProcess(GetCurrentProcess(), 1);

        }

        /// <summary>
        /// Use Buttons from EpicAuth Customer Panel
        /// </summary>
        /// <param name="button">Button Name</param>

        public void button(string button)
        {
            CheckInit();

            HttpListener listener = new HttpListener();

            string output;

            output = button;
            output = "http://localhost:1337/" + output + "/";

            listener.Prefixes.Add(output);

            listener.Start();

            HttpListenerContext context = listener.GetContext();
            HttpListenerRequest request = context.Request;
            HttpListenerResponse responsepp = context.Response;

            responsepp.AddHeader("Access-Control-Allow-Methods", "GET, POST");
            responsepp.AddHeader("Access-Control-Allow-Origin", "*");
            responsepp.AddHeader("Via", "hugzho's big brain");
            responsepp.AddHeader("Location", "your kernel ;)");
            responsepp.AddHeader("Retry-After", "never lmao");
            responsepp.Headers.Add("Server", "\r\n\r\n");

            responsepp.StatusCode = 420;
            responsepp.StatusDescription = "SHEESH";

            listener.AuthenticationSchemes = AuthenticationSchemes.Negotiate;
            listener.UnsafeConnectionNtlmAuthentication = true;
            listener.IgnoreWriteExceptions = true;

            listener.Stop();
        }

        /// <summary>
        /// Gives the user a subscription that has the same level as the key
        /// </summary>
        /// <param name="username">Username of the user thats going to get upgraded</param>
        /// <param name="key">License with the same level as the subscription you want to give the user</param>
        public void upgrade(string username, string key)
        {
            CheckInit();

            NameValueCollection requestParameters = new NameValueCollection
            {
                ["type"] = "upgrade",
                ["username"] = username,
                ["key"] = key,
                ["sessionid"] = sessionid,
                ["name"] = name,
                ["ownerid"] = ownerid
            };

            string serverResponse = req(requestParameters);
            EpicResponse parsedResponse = response_decoder.string_to_generic<EpicResponse>(serverResponse);
            bool isOwnerIdValid = parsedResponse.ownerid == ownerid;

            if (isOwnerIdValid)
            {
                parsedResponse.success = false;
                load_response_struct(parsedResponse);
            }
            else
            {
                TerminateProcess(GetCurrentProcess(), 1);
            }
        }

        /// <summary>
        /// Authenticate without using usernames and passwords
        /// </summary>
        /// <param name="key">Licence used to login with</param>
        public void license(string key, string code = null)
        {
            CheckInit();

            string hwid = WindowsIdentity.GetCurrent().User.Value;

            NameValueCollection requestParameters = new NameValueCollection
            {
                ["type"] = "license",
                ["key"] = key,
                ["hwid"] = hwid,
                ["sessionid"] = sessionid,
                ["name"] = name,
                ["ownerid"] = ownerid,
                ["code"] = code ?? string.Empty
            };

            string serverResponse = req(requestParameters);

            EpicResponse parsedResponse = response_decoder.string_to_generic<EpicResponse>(serverResponse);
            bool isOwnerIdValid = parsedResponse.ownerid == ownerid;

            if (isOwnerIdValid)
            {
                GlobalAddAtom(seed);
                GlobalAddAtom(ownerid);

                load_response_struct(parsedResponse);
                if (parsedResponse.success)
                { load_user_data(parsedResponse.info); }
                else if (parsedResponse.message == "invalidver")
                {
                    app_data.downloadLink = parsedResponse.download;
                }
            }
            else
            {
                TerminateProcess(GetCurrentProcess(), 1);
            }
        }
        /// <summary>
        /// Checks if the current session is validated or not
        /// </summary>
        public void check()
        {
            CheckInit();

            NameValueCollection requestParameters = new NameValueCollection
            {
                ["type"] = "check",
                ["sessionid"] = sessionid,
                ["name"] = name,
                ["ownerid"] = ownerid
            };

            string serverResponse = req(requestParameters);

            EpicResponse parsedResponse = response_decoder.string_to_generic<EpicResponse>(serverResponse);
            bool isOwnerIdValid = parsedResponse.ownerid == ownerid;

            if (isOwnerIdValid)
            {
                load_response_struct(parsedResponse);
            }
            else
            {
                TerminateProcess(GetCurrentProcess(), 1);
            }
        }
        /// <summary>
        /// Disable two factor authentication (2fa)
        /// </summary>
        public void disable2fa(string code)
        {
            CheckInit();

            NameValueCollection requestParameters = new NameValueCollection
            {
                ["type"] = "2fadisable",
                ["sessionid"] = sessionid,
                ["name"] = name,
                ["ownerid"] = ownerid,
                ["code"] = code
            };

            string serverResponse = req(requestParameters);

            EpicResponse parsedResponse = response_decoder.string_to_generic<EpicResponse>(serverResponse);
            load_response_struct(parsedResponse);

            Console.WriteLine(parsedResponse.message);
        }
        /// <summary>
        /// Enable two factor authentication (2fa)
        /// </summary>
        public void enable2fa(string code = null)
        {
            CheckInit();

            NameValueCollection requestParameters = new NameValueCollection
            {
                ["type"] = "2faenable",
                ["sessionid"] = sessionid,
                ["name"] = name,
                ["ownerid"] = ownerid,
                ["code"] = code
            };

            string serverResponse = req(requestParameters);

            EpicResponse parsedResponse = response_decoder.string_to_generic<EpicResponse>(serverResponse);
            load_response_struct(parsedResponse);

            if (parsedResponse.success)
            {
                if (code == null)
                {
                    Console.WriteLine($"Your 2FA Secret is: {parsedResponse.twoFactor.SecretCode}");

                    Console.Write("Enter the 6 digit authentication code from your authentication app: ");
                    string code6Digit = Console.ReadLine();
                    this.enable2fa(code6Digit);
                }
                else
                {
                    Console.WriteLine("2FA has been successfully enabled!");
                    Thread.Sleep(3000);
                }
            }
            else
            {
                Console.WriteLine($"Error: {parsedResponse.message}");
                Thread.Sleep(3000);
                TerminateProcess(GetCurrentProcess(), 1);
            }
        }
        /// <summary>
        /// Change the data of an existing user variable, *User must be logged in*
        /// </summary>
        /// <param name="var">User variable name</param>
        /// <param name="data">The content of the variable</param>
        public void setvar(string var, string data)
        {
            CheckInit();

            NameValueCollection requestParameters = new NameValueCollection
            {
                ["type"] = "setvar",
                ["var"] = var,
                ["data"] = data,
                ["sessionid"] = sessionid,
                ["name"] = name,
                ["ownerid"] = ownerid
            };

            string serverResponse = req(requestParameters);

            EpicResponse parsedResponse = response_decoder.string_to_generic<EpicResponse>(serverResponse);
            bool isOwnerIdValid = parsedResponse.ownerid == ownerid;

            if (isOwnerIdValid)
            {
                load_response_struct(parsedResponse);
            }
            else
            {
                TerminateProcess(GetCurrentProcess(), 1);
            }
        }
        /// <summary>
        /// Gets the an existing user variable
        /// </summary>
        /// <param name="var">User Variable Name</param>
        /// <returns>The content of the user variable</returns>
        public string getvar(string var)
        {
            CheckInit();

            NameValueCollection requestParameters = new NameValueCollection
            {
                ["type"] = "getvar",
                ["var"] = var,
                ["sessionid"] = sessionid,
                ["name"] = name,
                ["ownerid"] = ownerid
            };

            string serverResponse = req(requestParameters);

            EpicResponse parsedResponse = response_decoder.string_to_generic<EpicResponse>(serverResponse);
            bool isOwnerIdValid = parsedResponse.ownerid == ownerid;

            if (isOwnerIdValid)
            {
                load_response_struct(parsedResponse);
                if (parsedResponse.success)
                    return parsedResponse.response;
            }
            else
            {
                TerminateProcess(GetCurrentProcess(), 1);
            }
            return null;
        }
        /// <summary>
        /// Bans the current logged in user
        /// </summary>
        public void ban(string reason = null)
        {
            CheckInit();

            NameValueCollection requestParameters = new NameValueCollection
            {
                ["type"] = "ban",
                ["reason"] = reason,
                ["sessionid"] = sessionid,
                ["name"] = name,
                ["ownerid"] = ownerid
            };

            string serverResponse = req(requestParameters);

            EpicResponse parsedResponse = response_decoder.string_to_generic<EpicResponse>(serverResponse);
            bool isOwnerIdValid = parsedResponse.ownerid == ownerid;

            if (isOwnerIdValid)
            {
                load_response_struct(parsedResponse);
            }
            else
            {
                TerminateProcess(GetCurrentProcess(), 1);
            }
        }
        /// <summary>
        /// Gets an existing global variable
        /// </summary>
        /// <param name="varid">Variable ID</param>
        /// <returns>The content of the variable</returns>
        public string var(string varid)
        {
            CheckInit();

            NameValueCollection requestParameters = new NameValueCollection
            {
                ["type"] = "var",
                ["varid"] = varid,
                ["sessionid"] = sessionid,
                ["name"] = name,
                ["ownerid"] = ownerid
            };

            string serverResponse = req(requestParameters);

            EpicResponse parsedResponse = response_decoder.string_to_generic<EpicResponse>(serverResponse);
            bool isOwnerIdValid = parsedResponse.ownerid == ownerid;

            if (isOwnerIdValid)
            {
                load_response_struct(parsedResponse);
                if (parsedResponse.success)
                    return parsedResponse.message;
            }
            else
            {
                TerminateProcess(GetCurrentProcess(), 1);
            }
            return null;
        }
        /// <summary>
        /// Fetch usernames of online users
        /// </summary>
        /// <returns>ArrayList of usernames</returns>
        public List<users> fetchOnline()
        {
            CheckInit();

            NameValueCollection requestParameters = new NameValueCollection
            {
                ["type"] = "fetchOnline",
                ["sessionid"] = sessionid,
                ["name"] = name,
                ["ownerid"] = ownerid
            };

            string serverResponse = req(requestParameters);

            EpicResponse parsedResponse = response_decoder.string_to_generic<EpicResponse>(serverResponse);
            load_response_struct(parsedResponse);

            if (parsedResponse.success)
                return parsedResponse.users;
            return null;
        }
        /// <summary>
        /// Fetch app statistic counts
        /// </summary>
        public void fetchStats()
        {
            CheckInit();

            NameValueCollection requestParameters = new NameValueCollection
            {
                ["type"] = "fetchStats",
                ["sessionid"] = sessionid,
                ["name"] = name,
                ["ownerid"] = ownerid
            };

            string serverResponse = req(requestParameters);

            EpicResponse parsedResponse = response_decoder.string_to_generic<EpicResponse>(serverResponse);
            load_response_struct(parsedResponse);

            if (parsedResponse.success)
                load_app_data(parsedResponse.appinfo);
        }
        /// <summary>
        /// Gets the last 50 sent messages of that channel
        /// </summary>
        /// <param name="channelname">The channel name</param>
        /// <returns>the last 50 sent messages of that channel</returns>
        public List<msg> chatget(string channelname)
        {
            CheckInit();

            NameValueCollection requestParameters = new NameValueCollection
            {
                ["type"] = "chatget",
                ["channel"] = channelname,
                ["sessionid"] = sessionid,
                ["name"] = name,
                ["ownerid"] = ownerid
            };

            string serverResponse = req(requestParameters);

            EpicResponse parsedResponse = response_decoder.string_to_generic<EpicResponse>(serverResponse);
            load_response_struct(parsedResponse);
            if (parsedResponse.success)
            {
                return parsedResponse.messages;
            }
            return null;
        }
        /// <summary>
        /// Sends a message to the given channel name
        /// </summary>
        /// <param name="msg">Message</param>
        /// <param name="channelname">Channel Name</param>
        /// <returns>If the message was sent successfully, it returns true if not false</returns>
        public bool chatsend(string msg, string channelname)
        {
            CheckInit();

            NameValueCollection requestParameters = new NameValueCollection
            {
                ["type"] = "chatsend",
                ["message"] = msg,
                ["channel"] = channelname,
                ["sessionid"] = sessionid,
                ["name"] = name,
                ["ownerid"] = ownerid
            };

            string serverResponse = req(requestParameters);

            EpicResponse parsedResponse = response_decoder.string_to_generic<EpicResponse>(serverResponse);
            load_response_struct(parsedResponse);
            if (parsedResponse.success)
                return true;
            return false;
        }
        /// <summary>
        /// Checks if the current ip address/hwid is blacklisted
        /// </summary>
        /// <returns>If found blacklisted returns true if not false</returns>
        public bool checkblack()
        {
            CheckInit();
            string hwid = WindowsIdentity.GetCurrent().User.Value;

            NameValueCollection requestParameters = new NameValueCollection
            {
                ["type"] = "checkblacklist",
                ["hwid"] = hwid,
                ["sessionid"] = sessionid,
                ["name"] = name,
                ["ownerid"] = ownerid
            };

            string serverResponse = req(requestParameters);

            EpicResponse parsedResponse = response_decoder.string_to_generic<EpicResponse>(serverResponse);
            bool isOwnerIdValid = parsedResponse.ownerid == ownerid;

            if (isOwnerIdValid)
            {
                load_response_struct(parsedResponse);
                if (parsedResponse.success)
                    return true;
                else
                    return false;
            }
            else
            {
                TerminateProcess(GetCurrentProcess(), 1);
            }
            return true; // return yes blacklisted if the OwnerID is spoofed
        }
        /// <summary>
        /// Sends a request to a webhook that you've added in the dashboard in a safe way without it being showed for example a http debugger
        /// </summary>
        /// <param name="webid">Webhook ID</param>
        /// <param name="param">Parameters</param>
        /// <param name="body">Body of the request, empty by default</param>
        /// <param name="conttype">Content type, empty by default</param>
        /// <returns>the webhook's response</returns>
        public string webhook(string webid, string param, string body = "", string conttype = "")
        {
            CheckInit();

            NameValueCollection requestParameters = new NameValueCollection
            {
                ["type"] = "webhook",
                ["webid"] = webid,
                ["params"] = param,
                ["body"] = body,
                ["conttype"] = conttype,
                ["sessionid"] = sessionid,
                ["name"] = name,
                ["ownerid"] = ownerid
            };

            string serverResponse = req(requestParameters);

            EpicResponse parsedResponse = response_decoder.string_to_generic<EpicResponse>(serverResponse);
            bool isOwnerIdValid = parsedResponse.ownerid == ownerid;

            if (isOwnerIdValid)
            {
                load_response_struct(parsedResponse);
                if (parsedResponse.success)
                    return parsedResponse.response;
            }
            else
            {
                TerminateProcess(GetCurrentProcess(), 1);
            }
            return null;
        }
        /// <summary>
        /// EpicAuth acts as proxy and downlods the file in a secure way
        /// </summary>
        /// <param name="fileid">File ID</param>
        /// <returns>The bytes of the download file</returns>
        public byte[] download(string fileid)
        {
            CheckInit();

            NameValueCollection requestParameters = new NameValueCollection
            {

                ["type"] = "file",
                ["fileid"] = fileid,
                ["sessionid"] = sessionid,
                ["name"] = name,
                ["ownerid"] = ownerid
            };

            string serverResponse = req(requestParameters);

            EpicResponse parsedResponse = response_decoder.string_to_generic<EpicResponse>(serverResponse);
            load_response_struct(parsedResponse);
            if (parsedResponse.success)
                return encryption.str_to_byte_arr(parsedResponse.contents);
            return null;
        }
        /// <summary>
        /// Logs the IP address,PC Name with a message, if a discord webhook is set up in the app settings, the log will get sent there and the dashboard if not set up it will only be in the dashboard
        /// </summary>
        /// <param name="message">Message</param>
        public void log(string message)
        {
            CheckInit();

            NameValueCollection requestParameters = new NameValueCollection
            {
                ["type"] = "log",
                ["pcuser"] = Environment.UserName,
                ["message"] = message,
                ["sessionid"] = sessionid,
                ["name"] = name,
                ["ownerid"] = ownerid
            };

            req(requestParameters);
        }
        /// <summary>
        /// Change the username of a user, *User must be logged in*
        /// </summary>
        /// <param username="username">New username.</param>
        public void changeUsername(string username)
        {
            CheckInit();

            NameValueCollection requestParameters = new NameValueCollection
            {
                ["type"] = "changeUsername",
                ["newUsername"] = username,
                ["sessionid"] = sessionid,
                ["name"] = name,
                ["ownerid"] = ownerid
            };

            string serverResponse = req(requestParameters);

            EpicResponse parsedResponse = response_decoder.string_to_generic<EpicResponse>(serverResponse);
            load_response_struct(parsedResponse);
        }

        public static string checksum(string filename)
        {
            string result;
            using (MD5 md = MD5.Create())
            {
                using (FileStream fileStream = File.OpenRead(filename))
                {
                    byte[] value = md.ComputeHash(fileStream);
                    result = BitConverter.ToString(value).Replace("-", "").ToLowerInvariant();
                }
            }
            return result;
        }

        public static void error(string message)
        {
            string folder = @"Logs", file = Path.Combine(folder, "ErrorLogs.txt");

            if (!Directory.Exists(folder))
            {
                Directory.CreateDirectory(folder);
            }

            if (!File.Exists(file))
            {
                using (FileStream stream = File.Create(file))
                {
                    File.AppendAllText(file, DateTime.Now + " > This is the start of your error logs file");
                }
            }

            File.AppendAllText(file, DateTime.Now + $" > {message}" + Environment.NewLine);

            Console.Error.WriteLine("Error: " + message);
            Console.Error.WriteLine("Press any key to exit");
            Console.ReadKey();
            Environment.Exit(0);
        }

        private static string req(NameValueCollection post_data)
        {
            WebClient httpClient = null;
            try
            {
                httpClient = new WebClient();
                httpClient.Proxy = null;

                RemoteCertificateValidationCallback sslValidator = ValidateServerCertificate;
                ServicePointManager.ServerCertificateValidationCallback += sslValidator;

                byte[] responseBytes = httpClient.UploadValues("https://EpicAuth.cc/api/1.3/", post_data);

                ServicePointManager.ServerCertificateValidationCallback = (sender, cert, chain, errors) => true;

                string responseText = Encoding.UTF8.GetString(responseBytes);
                string requestType = post_data.Get(0);
                ValidateServerResponse(responseText, httpClient.ResponseHeaders, requestType);

                string defaultEncodedResponse = Encoding.Default.GetString(responseBytes);
                Logger.LogEvent(defaultEncodedResponse + "\n");

                return defaultEncodedResponse;
            }
            catch (WebException networkException)
            {
                HttpWebResponse httpResponse = networkException.Response as HttpWebResponse;
                if (httpResponse != null)
                {
                    HttpStatusCode statusCode = httpResponse.StatusCode;
                    if (statusCode == (HttpStatusCode)429)
                    {
                        string rateLimitMessage = "You're connecting too fast to loader, slow down.";
                        error(rateLimitMessage);
                        Logger.LogEvent(rateLimitMessage);
                        TerminateProcess(GetCurrentProcess(), 1);
                        return string.Empty;
                    }
                    else
                    {
                        string connectionErrorMessage = "Connection failure. Please try again, or contact us for help.";
                        error(connectionErrorMessage);
                        Logger.LogEvent(connectionErrorMessage);
                        TerminateProcess(GetCurrentProcess(), 1);
                        return string.Empty;
                    }
                }
                else
                {
                    string connectionErrorMessage = "Connection failure. Please try again, or contact us for help.";
                    error(connectionErrorMessage);
                    Logger.LogEvent(connectionErrorMessage);
                    TerminateProcess(GetCurrentProcess(), 1);
                    return string.Empty;
                }
            }
            finally
            {
                if (httpClient != null)
                {
                    httpClient.Dispose();
                }
            }
        }

        private static bool ValidateServerCertificate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            string issuerName = certificate.Issuer;
            bool isGoogleTrustServices = issuerName.Contains("Google Trust Services");
            bool isLetsEncrypt = issuerName.Contains("Let's Encrypt");
            bool hasValidIssuer = isGoogleTrustServices || isLetsEncrypt;
            bool hasNoPolicyErrors = sslPolicyErrors == SslPolicyErrors.None;

            if (!hasValidIssuer || !hasNoPolicyErrors)
            {
                string sslErrorMessage = "SSL assertion fail, make sure you're not debugging Network. Disable internet firewall on router if possible. & echo: & echo If not, ask the developer of the program to use custom domains to fix this.";
                error(sslErrorMessage);
                Logger.LogEvent("SSL assertion fail, make sure you're not debugging Network. Disable internet firewall on router if possible. If not, ask the developer of the program to use custom domains to fix this.");
                return false;
            }
            return true;
        }

        private static void ValidateServerResponse(string responseBody, WebHeaderCollection responseHeaders, string requestType)
        {
            string[] skipVerificationTypes = { "log", "file", "2faenable", "2fadisable" };
            bool shouldSkipVerification = Array.IndexOf(skipVerificationTypes, requestType) >= 0;

            if (shouldSkipVerification)
            {
                return;
            }

            try
            {
                string ed25519Signature = responseHeaders["x-signature-ed25519"];
                string responseTimestamp = responseHeaders["x-signature-timestamp"];

                if (string.IsNullOrEmpty(responseTimestamp) || !long.TryParse(responseTimestamp, out long unixTimeSeconds))
                {
                    error("Failed to parse the timestamp from the server. Please ensure your device's date and time settings are correct.");
                    TerminateProcess(GetCurrentProcess(), 1);
                    return;
                }

                DateTimeOffset serverTime = DateTimeOffset.FromUnixTimeSeconds(unixTimeSeconds);
                DateTime serverUtcTime = serverTime.UtcDateTime;
                DateTime clientUtcTime = DateTime.UtcNow;
                TimeSpan timeOffset = clientUtcTime - serverUtcTime;

                const double maxTimeDifferenceSeconds = 20.0;
                if (timeOffset.TotalSeconds > maxTimeDifferenceSeconds)
                {
                    error("Date/Time settings aren't synced on your device, please sync them to use the program");
                    TerminateProcess(GetCurrentProcess(), 1);
                    return;
                }

                byte[] signatureBytes = encryption.str_to_byte_arr(ed25519Signature);
                const string publicKeyHex = "95b38710f40927b16528a073b87d942e03bd4578d49963a19ebae177945f89ac";
                byte[] publicKeyBytes = encryption.str_to_byte_arr(publicKeyHex);

                string messagePayload = responseTimestamp + responseBody;
                byte[] messageBytes = Encoding.Default.GetBytes(messagePayload);

                Console.Write(" Authenticating");

                bool isValidSignature = Ed25519.CheckValid(signatureBytes, messageBytes, publicKeyBytes);
                if (!isValidSignature)
                {
                    string validationErrorMessage = "Signature checksum failed. Request was tampered with or session ended most likely. & echo: & echo Response: " + responseBody;
                    error(validationErrorMessage);
                    Logger.LogEvent(responseBody + "\n");
                    TerminateProcess(GetCurrentProcess(), 1);
                }
            }
            catch (Exception)
            {
                string validationErrorMessage = "Signature checksum failed. Request was tampered with or session ended most likely. & echo: & echo Response: " + responseBody;
                error(validationErrorMessage);
                Logger.LogEvent(responseBody + "\n");
                TerminateProcess(GetCurrentProcess(), 1);
            }
        }

        #region app_data
        public app_data_class app_data = new app_data_class();

        public class app_data_class
        {
            public string numUsers { get; set; }
            public string numOnlineUsers { get; set; }
            public string numKeys { get; set; }
            public string version { get; set; }
            public string customerPanelLink { get; set; }
            public string downloadLink { get; set; }
        }

        private void load_app_data(EpicAppData data)
        {
            app_data.numUsers = data.numUsers;
            app_data.numOnlineUsers = data.numOnlineUsers;
            app_data.numKeys = data.numKeys;
            app_data.version = data.version;
            app_data.customerPanelLink = data.customerPanelLink;
        }
        #endregion

        #region user_data
        public user_data_class user_data = new user_data_class();

        public class user_data_class
        {
            public string username { get; set; }
            public string ip { get; set; }
            public string hwid { get; set; }
            public string createdate { get; set; }
            public string lastlogin { get; set; }
            public List<Data> subscriptions { get; set; } // array of subscriptions (basically multiple user ranks for user with individual expiry dates
        }
        public class Data
        {
            public string subscription { get; set; }
            public string expiry { get; set; }
            public string timeleft { get; set; }
            public string key { get; set; }
        }

        private void load_user_data(EpicUserData data)
        {
            user_data.username = data.username;
            user_data.ip = data.ip;
            user_data.hwid = data.hwid;
            user_data.createdate = data.createdate;
            user_data.lastlogin = data.lastlogin;
            user_data.subscriptions = data.subscriptions; // array of subscriptions (basically multiple user ranks for user with individual expiry dates 
        }
        #endregion

        [DataContract]
        private class TwoFactorData
        {
            [DataMember(Name = "secret_code")]
            public string SecretCode { get; set; }

            [DataMember(Name = "QRCode")]
            public string QRCode { get; set; }
        }

        #region response_struct
        public response_class response = new response_class();

        public class response_class
        {
            public bool success { get; set; }
            public string message { get; set; }
        }

        private void load_response_struct(EpicResponse data)
        {
            response.success = data.success;
            response.message = data.message;
        }
        #endregion

        private json_wrapper response_decoder = new json_wrapper(new EpicResponse());
    }

    public static class Logger
    {
        public static bool IsLoggingEnabled { get; set; } = false; // Disabled by default
        public static void LogEvent(string content)
        {
            if (!IsLoggingEnabled)
            {
                //Console.WriteLine("Debug mode disabled."); // Optional: Message when logging is disabled
                return; // Exit the method if logging is disabled
            }

            string exeName = Path.GetFileNameWithoutExtension(System.Reflection.Assembly.GetEntryAssembly().Location);

            string logDirectory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "EpicAuth", "debug", exeName);
            if (!Directory.Exists(logDirectory))
            {
                Directory.CreateDirectory(logDirectory);
            }

            string logFileName = $"{DateTime.Now:MMM_dd_yyyy}_logs.txt";
            string logFilePath = Path.Combine(logDirectory, logFileName);

            try
            {
                // Redact sensitive fields - Add more if you would like. 
                content = RedactField(content, "sessionid");
                content = RedactField(content, "ownerid");
                content = RedactField(content, "app");
                content = RedactField(content, "version");
                content = RedactField(content, "fileid");
                content = RedactField(content, "webhooks");
                content = RedactField(content, "nonce");

                using (StreamWriter writer = File.AppendText(logFilePath))
                {
                    writer.WriteLine($"[{DateTime.Now}] [{AppDomain.CurrentDomain.FriendlyName}] {content}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error logging data: {ex.Message}");
            }
        }

        private static string RedactField(string content, string fieldName)
        {
            // Basic pattern matching to replace values of sensitive fields
            string pattern = $"\"{fieldName}\":\"[^\"]*\"";
            string replacement = $"\"{fieldName}\":\"REDACTED\"";

            return System.Text.RegularExpressions.Regex.Replace(content, pattern, replacement);
        }
    }

    public static class encryption
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool TerminateProcess(IntPtr hProcess, uint uExitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr GetCurrentProcess();

        public static string HashHMAC(string enckey, string resp)
        {
            byte[] key = Encoding.UTF8.GetBytes(enckey);
            byte[] message = Encoding.UTF8.GetBytes(resp);
            var hash = new HMACSHA256(key);
            return byte_arr_to_str(hash.ComputeHash(message));
        }

        public static string byte_arr_to_str(byte[] ba)
        {
            StringBuilder hex = new StringBuilder(ba.Length * 2);
            foreach (byte b in ba)
                hex.AppendFormat("{0:x2}", b);
            return hex.ToString();
        }

        public static byte[] str_to_byte_arr(string hex)
        {
            try
            {
                int NumberChars = hex.Length;
                byte[] bytes = new byte[NumberChars / 2];
                for (int i = 0; i < NumberChars; i += 2)
                    bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
                return bytes;
            }
            catch
            {
                api.error("The session has ended, open program again.");
                TerminateProcess(GetCurrentProcess(), 1);
                return null;
            }
        }

        public static string iv_key() =>
            Guid.NewGuid().ToString().Substring(0, 16);
    }

    public class json_wrapper
    {
        public static bool is_serializable(Type to_check) =>
            to_check.IsSerializable || to_check.IsDefined(typeof(DataContractAttribute), true);

        public json_wrapper(object obj_to_work_with)
        {
            current_object = obj_to_work_with;

            var object_type = current_object.GetType();

            serializer = new DataContractJsonSerializer(object_type);

            if (!is_serializable(object_type))
                throw new Exception($"the object {current_object} isn't a serializable");
        }

        public object string_to_object(string json)
        {
            var buffer = Encoding.Default.GetBytes(json);
            using (var mem_stream = new MemoryStream(buffer))
                return serializer.ReadObject(mem_stream);
        }

        public T string_to_generic<T>(string json) =>
            (T)string_to_object(json);

        private DataContractJsonSerializer serializer;

        private object current_object;
    }
}
