using System;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.Net.NetworkInformation;
using System.Security;

namespace ActiveDirectorySearch
{
    class Program
    {
        //main method OBVIOUSLY
        static void Main(string[] args)
        {
            var pc = ValidateCredentials();
            if(pc == null)
                Environment.Exit(1);
            AccessControl.StartAccessControl(pc);
        }

        //method to show star when password is typed
        private static SecureString GetPassword()
        {
            var pwd = new SecureString();
            while (true)
            {
                ConsoleKeyInfo i = Console.ReadKey(true);
                if (i.Key == ConsoleKey.Enter)
                {
                    break;
                }
                else if (i.Key == ConsoleKey.Backspace)
                {
                    if (pwd.Length > 0)
                    {
                        pwd.RemoveAt(pwd.Length - 1);
                        Console.Write("\b \b");
                    }
                }
                else
                {
                    pwd.AppendChar(i.KeyChar);
                    Console.Write("*");
                }
            }
            Console.Write("\n");
            return pwd;
        }

        //validates credentials, loops until correct; starts connection methods
        private static Tuple<PrincipalContext, DirectoryEntry> ValidateCredentials()
        {
            PrincipalContext pc = null;
            Tuple<PrincipalContext, DirectoryEntry> returnTuple = null;
            PrincipalContext connectPc = null;
            DirectoryEntry connectDe = null;
            var domain = IPGlobalProperties.GetIPGlobalProperties().DomainName;

            Console.Write("Username: ");
            string username = Console.ReadLine();
            Console.Write("Password: ");
            string password = new System.Net.NetworkCredential(string.Empty, GetPassword()).Password;
            try
            {
                pc = new PrincipalContext(ContextType.Domain, domain);
                if (!pc.ValidateCredentials(username, password))
                {
                    Console.WriteLine("Wrong username or password!");
                    return ValidateCredentials();
                }
                connectPc = ConnectPrincipal(username, password, domain);
                connectDe = new DirectoryEntry("LDAP://" + IPGlobalProperties.GetIPGlobalProperties().DomainName);
                connectDe.AuthenticationType = AuthenticationTypes.Secure;
                returnTuple = new Tuple<PrincipalContext, DirectoryEntry>(connectPc, connectDe);
            }
            catch(Exception e)
            {
                Console.WriteLine("Error: " + e.Message);
            }
            return returnTuple;
        }

        //connects to LDAP using 'PrincipalContext' class - new way
        private static PrincipalContext ConnectPrincipal(string username, string password, string domain)
        {
            PrincipalContext pc = null;
            try
            {
                pc = new PrincipalContext(ContextType.Domain, domain, username, password);
            }
            catch (Exception e)
            {
                Console.WriteLine("\nError: " + e.Message);
            }
            return pc;
        }

        //connects to LDAP using 'DirectoryEntry' class - old way
        public static DirectoryEntry ConnectDirectory(string username, string password)
        {
            DirectoryEntry de = null;
            try
            {
                de = new DirectoryEntry("LDAP://" + IPGlobalProperties.GetIPGlobalProperties().DomainName);
                de.AuthenticationType = AuthenticationTypes.Secure;
            }
            catch(Exception e)
            {
                Console.WriteLine("\nError: " + e.Message);
            }
            return de;
        }
    }
}
