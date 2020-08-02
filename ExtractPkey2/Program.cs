using System;
using System.IO;
using Mono.Options;

namespace ExtractPkey
{
    internal class Program
    {
        private static OptionSet options;

        private static void Main(string[] args)
        {
            string folder = null, name = null, pin = null;
            Mode mode = Mode.Private;
            bool showHelp = false;

            options = new OptionSet
            {
                {"f|folder=", "Путь к контейнеру", f => folder = f},
                {"r|reg=", "Имя контейнера в реестре", r => name = r},
                {
                    "private", "Извлечь закрытый ключ (по умолчанию)", p =>
                    {
                        if (p != null) mode = Mode.Private;
                    }
                },
                {
                    "cert", "Извлечь сертификат", c =>
                    {
                        if (c != null) mode = Mode.Certificate;
                    }
                },
                {"p|pin=", "ПИН-код", p => pin = p},
                {"h|help", "Помощь", h => showHelp = h != null}
            };

            try
            {
                options.Parse(args);
            } catch (OptionException e)
            {
                Console.Error.WriteLine(e.Message);
                return;
            }

            if (showHelp)
            {
                PrintHelp();
                return;
            }

            Container container = null;
            if (!string.IsNullOrEmpty(folder))
                container = new FolderContainer(folder, pin);
            else if (!string.IsNullOrEmpty(name)) container = new RegistryContainer(name, pin);

            if (container == null)
            {
                PrintHelp();
                return;
            }

            IExport export;
            if (mode == Mode.Certificate)
                export = new CertificateExport();
            else
                export = new PrivateKeyExport();

        
                //  Stream openStandardOutput = Console.OpenStandardOutput();
                MemoryStreamA mem = new MemoryStreamA();
                
                mem.Close();
                    export.Export(container, mem);
                    
                    using (StreamReader streamReader = new StreamReader(mem))
                    {
                        mem.Position = 0;
                        string result = streamReader.ReadToEnd();
                        Console.WriteLine(result);
                        mem.CloseReal();
                    } 
            
        }

        private static void PrintHelp()
        {
            Console.WriteLine("Использование: extractpkey {ПАРАМЕТРЫ}");
            Console.WriteLine("Извлечение данных из контейнера Крипто ПРО");
            Console.WriteLine();
            Console.WriteLine("Параметры:");
            options.WriteOptionDescriptions(Console.Out);
        }

        private enum Mode
        {
            Private,
            Certificate
        }
    }
    
    class MemoryStreamA : MemoryStream
    {

        public override void Close()
        {
           // base.Close();
        }

        public void CloseReal()
        {
             base.Close();
        }

    }
}