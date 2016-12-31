using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.Linq;
using System.Management;
using System.Text;
using System.Threading.Tasks;

namespace ActiveDirectorySearch
{
    class AccessControl
    {


        //starts access control testing procedures
        public static void StartAccessControl(PrincipalContext pc)
        {
            //TestMethod(pc);
            PrivilegedAccess(pc);
        }

        //privileged access control procedures
        private static void PrivilegedAccess(PrincipalContext pc)
        {
            List<string> privilegedGroups = new List<string>(new string[] { "Domain Admins"});
            List<string> privilegedGroupsFull = new List<string>(new string[] { "Domain Admins",
                "Administrators", "Enterprise Admins", "Group Policy Admins", "Schema Admins",
                "DNS Admins", "Account Operators", "Server Operators"});
            List<UserPrincipal> privilegedUsers = new List<UserPrincipal>();
            foreach (var listGroup in privilegedGroups)
            {
                //Console.WriteLine("\n{0}\n", listGroup);
                var gp = new GroupPrincipal(pc, listGroup);
                var searcher = new PrincipalSearcher();
                searcher.QueryFilter = gp;
                var group = searcher.FindOne() as GroupPrincipal;
                if (group == null)
                {
                    Console.WriteLine("Group is empty.");
                }
                else
                {
                    getAllUserPrinicpals(ref privilegedUsers, group);
                }
            }

            var privHash = new HashSet<UserPrincipal>(privilegedUsers);
            foreach (var item in privHash)
            {
                Console.WriteLine(item.Name + "----" + item.PasswordNeverExpires);
            }
        }

        //gets all users in a list
        public static void getAllUserPrinicpals(ref List<UserPrincipal> principals, GroupPrincipal principal)
        {
            foreach (Principal princ in principal.Members)
            {
                if (princ is UserPrincipal)
                    principals.Add((UserPrincipal)princ);
                else if (princ is GroupPrincipal)
                    getAllUserPrinicpals(ref principals, (GroupPrincipal)princ);
            }
        }

        //starts two test methods
        private static void TestMethod(PrincipalContext pc)
        {
            Console.Write("\n\nOptions:\n< 1 > Search for a particular user\n< 2 > Show 'password never expires' users\n>>Choice: ");
            string choice = Console.ReadLine();
            if (choice == "1")
                SearchUsingPrincipal(pc);
            else if (choice == "2")
                PasswordNeverExpiresUsers(pc);
            else
                Console.WriteLine("Incorrect!");
            Console.ReadLine();
        }

        //test method - search and display user
        private static void SearchUsingPrincipal(PrincipalContext pc)
        {

            Console.Write("\nSearch for user: ");
            string lookUp = Console.ReadLine();
            try
            {
                var up = new UserPrincipal(pc);
                up.SamAccountName = lookUp;
                PrincipalSearcher ps = new PrincipalSearcher(up);
                UserPrincipal result = (UserPrincipal)ps.FindOne();
                ps.Dispose();
                Console.WriteLine("Full name                                        :" + result.DisplayName);
                Console.WriteLine("Date and time the account was locked             :" + result.AccountLockoutTime);
                Console.WriteLine("Count of bad logons                              :" + result.BadLogonCount);
                Console.WriteLine("Account is enabled?                              :" + result.Enabled);
                Console.WriteLine("Date and time of last bad password attempt       :" + result.LastBadPasswordAttempt);
                Console.WriteLine("Password never expires?                          :" + result.PasswordNeverExpires);
                Console.WriteLine("\nAll certificates the user has:\n");
                var showCerts = result.Certificates;
                foreach (var cert in showCerts)
                {
                    Console.WriteLine(cert.ToString());
                }
                Console.WriteLine("\nAll groups the user is part of:\n");
                var showGroups = result.GetGroups();
                foreach (var group in showGroups)
                {
                    Console.WriteLine(group);
                }
            }
            catch (NullReferenceException)
            {
                Console.WriteLine("No user with this name.");
            }
            catch (Exception e)
            {
                Console.WriteLine("Error: " + e.Message);
            }
        }

        //test method - shows 'password never expire' accounts
        private static void PasswordNeverExpiresUsers(PrincipalContext pc)
        {
            try
            {
                var up = new UserPrincipal(pc);
                up.PasswordNeverExpires = true;
                PrincipalSearcher ps = new PrincipalSearcher(up);
                Console.WriteLine("\nPlease wait. I am counting!\n");
                var results = ps.FindAll();
                ps.Dispose();
                //up.Dispose();
                var yearAgo = DateTime.Now.AddYears(-1);
                int counter = 0;
                foreach (UserPrincipal user in results)
                {
                    if (user.LastLogon > yearAgo && user.Enabled == true)
                    {
                        counter++;
                    }
                }
                Console.WriteLine("\n-----> There are " + results.Count() + " users with password never expires!\n-----> " + counter + " of them are ENABLED and HAVE logged in during the last year.\n-----> Press \"s\" and return to list the accounts.");
                string keyPress = Console.ReadLine();
                if (keyPress == "s")
                {
                    Console.WriteLine("\nUsers with password never expire: ");
                    foreach (UserPrincipal user in results)
                    {
                        Console.WriteLine(user.DisplayName);
                    }
                }
                else
                {

                }
            }
            catch (System.DirectoryServices.DirectoryServicesCOMException)
            {
                Console.WriteLine("\nYou need to log in!");
            }
            catch (Exception e)
            {
                Console.WriteLine("Error: " + e.Message);
            }
        }
    }
}
