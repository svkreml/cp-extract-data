using System.IO;

namespace ExtractPkey
{
    internal class FolderContainer : Container
    {
        private readonly string _folderName;

        public FolderContainer(string folderName, string pin)
            : base(pin)
        {
            _folderName = folderName;
        }

        protected override Data LoadContainerData()
        {
            return new Data
            {
                Header = File.ReadAllBytes(Path.Combine(_folderName, "header.key")),
                Masks = File.ReadAllBytes(Path.Combine(_folderName, "masks.key")),
                Masks2 = File.ReadAllBytes(Path.Combine(_folderName, "masks2.key")),
                Name = File.ReadAllBytes(Path.Combine(_folderName, "name.key")),
                Primary = File.ReadAllBytes(Path.Combine(_folderName, "primary.key")),
                Primary2 = File.ReadAllBytes(Path.Combine(_folderName, "primary2.key"))
            };
        }
    }
}