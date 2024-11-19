//import sun.security.pkcs11.SunPKCS11;
//
//import java.lang.reflect.Constructor;
//
//public class PKCS11ProviderFactory {
//
//    public static SunPKCS11 createPKCS11Provider(Config config) throws Exception {
//        Constructor<SunPKCS11> constructor = SunPKCS11.class.getDeclaredConstructor(Config.class);
//        constructor.setAccessible(true);
//        return constructor.newInstance(config);
//    }
//}
