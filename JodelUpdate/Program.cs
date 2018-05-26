using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.SymbolStore;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using ELFSharp.ELF;
using ELFSharp.ELF.Sections;
using ICSharpCode.SharpZipLib.Zip;
using SharpDisasm;
using SharpDisasm.Udis86;

namespace JodelUpdate
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.Title = "JodelUpdater";

            Directory.CreateDirectory("apk");
            Directory.CreateDirectory("lib");

            Console.Write("Retrieving latest version... ");
            var latestVersion = GetLatestVersion();
            Console.WriteLine(latestVersion);

            var apkFile = "apk\\" + latestVersion + ".apk";
            var libFile = "lib\\" + latestVersion + ".so";

            if (!File.Exists(apkFile))
            {
                Console.WriteLine("APK does not exists...Downloading...");
                DownloadApk(apkFile);
                Thread.Sleep(5000);
            }

            
            if (!File.Exists(libFile))
            {
                Console.WriteLine("Trying to extract hmaclib (x86)...");
                ExtractLibFile(apkFile, libFile);
            }
            

            Console.WriteLine(" ");
            Console.WriteLine(" ");
            Console.WriteLine("You are up to date!");
            Console.WriteLine(" ");
            Console.WriteLine(" ");

            Console.WriteLine("Trying to extract hmacsecret from " + "lib\\" + latestVersion + ".so" + "...");

            var secret = ExtractKey(libFile);

            Console.WriteLine(" ");
            Console.WriteLine(" ");
            Console.WriteLine("HMAC secret:  " + secret);

            Console.ReadLine();
        }

        private static string GetLatestVersion()
        {
            var wc = new WebClient();

            var result = wc.DownloadString("https://apkpure.com/jodel-the-hyperlocal-app/com.tellm.android.app/download?from=details");

            return Regex.Match(result, "version_name: '(.*?)',").Groups[1].Value.Replace(".", "_");
        }

        private static void DownloadApk(string apkPath)
        {
            var wc = new WebClient();

            var result = wc.DownloadString("https://apkpure.com/jodel-the-hyperlocal-app/com.tellm.android.app/download?from=details");

            var path =  Regex.Match(result, "<iframe id=\"iframe_download\" src=\"(.*?)\"></iframe>\r").Groups[1].Value;

            var apkBytes = wc.DownloadData(path);

            File.WriteAllBytes(apkPath, apkBytes);
        }

        private static void ExtractLibFile(string apkPath, string libFile)
        {
            //apk is basically a zip file
            using (var s = new ZipInputStream(File.OpenRead(apkPath)))
            {

                ZipEntry theEntry;
                while ((theEntry = s.GetNextEntry()) != null)
                {
                    if (theEntry.IsFile && theEntry.Name.Contains("lib/x86/"))
                    {
                        var fileEntry = new List<byte>();
                        var data = new byte[4096];

                        var size = s.Read(data, 0, data.Length);
                        while (size > 0)
                        {
                            fileEntry.AddRange(data);
                            size = s.Read(data, 0, data.Length);
                        }

                        //hmac function
                        var found = BoyerMoore.Search("486d6163496e746572636570746f725f696e6974", fileEntry.ToArray()).Any();
                        if (found)
                        {
                            Console.WriteLine("Found matching lib file! Saving to " + libFile + " ...");
                            File.WriteAllBytes(libFile, fileEntry.ToArray());
                            break;
                        }
                    }

                }
                s.Close();
            }


        }

        //only working post v4.81
        private static string ExtractKey(string path)
        {
            Console.WriteLine("Loading ELF...");
            var elf = ELFReader.Load(path); //I386
            var functions = ((ISymbolTable)elf.GetSection(".dynsym")).Entries.Where(x => x.Type == SymbolType.Function);
            var hmacFunction = functions.FirstOrDefault(x => x.Name == "Java_com_jodelapp_jodelandroidv3_api_HmacInterceptor_init") as SymbolEntry<uint>;

            var start = (int)hmacFunction.Value;
            var size = (int)hmacFunction.Size;
            var bytes = File.ReadAllBytes(path).Skip(start).Take(size).ToArray();
            Console.WriteLine("Found function Java_com_jodelapp_jodelandroidv3_api_HmacInterceptor_init at 0x" + start.ToString("X"));

            Console.WriteLine("Disassemnling asm to c code...");

            Disassembler.Translator.ResolveRip = true;

            Disassembler.Translator.IncludeAddress = true;
            Disassembler.Translator.IncludeBinary = true;
            var disassembler = new Disassembler(bytes, ArchitectureMode.x86_32, 0, true);
            var asmInstruction = disassembler.Disassemble().ToList();


            var movs = asmInstruction.Where(x => x.Mnemonic == ud_mnemonic_code.UD_Imov && x.Length > 2);
            Console.WriteLine("Found " + movs.Count() + " movs...");
            var buf = new byte[100];
            //take lowest mov as offset
            var offset = (int)movs.OrderBy(x => x.Operands.OrderBy(y => y.Value).FirstOrDefault().Value).FirstOrDefault().Operands[0].Value;

            foreach (var mov in movs)
            {
                var off = mov.Operands[0].Value;
                if (mov.Operands[1].Size == 8)
                {
                    var val = mov.Operands[1].LvalByte;
                    buf[off - offset] = (byte)val;
                }
                if (mov.Operands[1].Size == 32)
                {
                    var val = mov.Operands[1].LvalUDWord;
                    var intBytes = BitConverter.GetBytes(val);
                    buf[off - offset] = intBytes[0];
                    buf[off - offset + 1] = intBytes[1];
                    buf[off - offset + 2] = intBytes[2];
                    buf[off - offset + 3] = intBytes[3];
                }
            }

            Console.WriteLine("Generated xor key...");
            Console.WriteLine("Trying to generate hmac secret...");
            var hmac = JodelCrypto.DecryptHmacSecret(buf);

            return hmac;
        }

    }
}
