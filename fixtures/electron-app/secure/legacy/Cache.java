import java.io.*;

class Cache {
    Object load(InputStream in) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(in);
        ois.setObjectInputFilter(ObjectInputFilter.Config.createFilter("com.example.model.*;!*"));
        return ois.readObject();
    }
}
