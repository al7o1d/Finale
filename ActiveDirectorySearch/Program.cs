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
            Console.Write("Username: ");
            string username = Console.ReadLine();
            Console.Write("Password: ");
            string password = new System.Net.NetworkCredential(string.Empty, GetPassword()).Password;
            var principalConnector = ConnectPrincipal(username, password);
            //var directoryConnector = ConnectDirectory(username, password);
            AccessControl.StartAccessControl(principalConnector);
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
            return pwd;
        }

        //connects to LDAP using 'PrincipalContext' class - new way
        private static PrincipalContext ConnectPrincipal(string username, string password)
        {
            PrincipalContext pc = null;
            try
            {
                var domain = IPGlobalProperties.GetIPGlobalProperties().DomainName;
                pc = new PrincipalContext(ContextType.Domain, domain);
                if (pc.ValidateCredentials(username, password))
                    pc = new PrincipalContext(ContextType.Domain, domain, username, password);
                else
                    Console.WriteLine("Wrong Credentials!");
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
