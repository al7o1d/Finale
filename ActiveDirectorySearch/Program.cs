using System;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.Linq;
using System.Net.NetworkInformation;
using System.Security;
using System.Security.Principal;

namespace ActiveDirectorySearch
{
    class Program
    {
        //main method OBVIOUSLY
        static void Main(string[] args)
        {
            var pc = ValidateCredentials();
            //var principalConnector = ConnectPrincipal(username, password);
            //var directoryConnector = ConnectDirectory(username, password);
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

        private static PrincipalContext ValidateCredentials()
        {
            PrincipalContext pc = null;
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
            }
            catch(Exception e)
            {
                Console.WriteLine("Error: " + e.Message);
            }
            var connect = ConnectPrincipal(username, password, domain);
            return connect;
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
        private static DirectoryEntry ConnectDirectory(string username, string password)
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
