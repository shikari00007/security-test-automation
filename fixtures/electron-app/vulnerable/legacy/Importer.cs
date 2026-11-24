using System.IO;
using System.Runtime.Serialization.Formatters.Binary;

class Importer {
    // var f = new BinaryFormatter();  (commented)
    object Load(Stream s) {
        var formatter = new BinaryFormatter();
        return formatter.Deserialize(s);
    }
}
