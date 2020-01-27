using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace ServiceManager
{
    class Program
    {
        #region WindowsVersionInformation
        static string[] Workstations = { "Win7", "Win8", "Win10", "WinXP" };
        static string[] Servers = { "Srv2000", "Srv2003", "Srv2008", "Srv2012", "Srv2016" };
        #endregion

        #region ServiceDefinitions
        static ServiceInformation SpoolerService()
        {
            ServiceInformation spooler = new ServiceInformation();
            spooler.DLLPath = "C:\\Windows\\System32\\ualapi.dll";
            spooler.ServiceName = "spooler";
            spooler.SupportedOperatingSystems = Workstations;
            return spooler;
        }

        static ServiceInformation Fax()
        {
            ServiceInformation spooler = new ServiceInformation();
            spooler.DLLPath = "C:\\Windows\\System32\\ualapi.dll";
            spooler.ServiceName = "fax";
            spooler.SupportedOperatingSystems = Workstations;
            return spooler;
        }

        static ServiceInformation[] GetSupportedServices()
        {
            // Declare additional supported services here
            ServiceInformation[] ret =
            {
                Fax(),
                SpoolerService(),
            };
            return ret;
        }
        #endregion

        static Dictionary<string, object> ParseArgs(string[] args)
        {
            Dictionary<string, object> results = new Dictionary<string, object>();
            results["force"] = false;
            foreach(string arg in args)
            {
                if (arg.Contains("="))
                {
                    string[] parts = arg.Split('=');
                    results[parts[0]] = parts[1];
                }
                else if (arg.Contains("--force"))
                {
                    results["force"] = true;
                }
            }

            return results;
        }

        static bool ValidateArguments(Dictionary<string, object> args)
        {
            if (!args.ContainsKey("service"))
            {
                return false;
            }
            else if (!args.ContainsKey("computername"))
            {
                return false;
            }
            return true;
        }

        static void Main(string[] args)
        {
            Dictionary<string, object> cmdArgs = ParseArgs(args);
            if (!cmdArgs.ContainsKey("service"))
            {

            }
        }
    }
}
