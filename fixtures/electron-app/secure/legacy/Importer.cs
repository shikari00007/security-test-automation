using System.IO;
using System.Text.Json;

class Importer {
    T Load<T>(Stream s) {
        return JsonSerializer.Deserialize<T>(s);
    }
}
