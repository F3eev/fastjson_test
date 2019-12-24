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
        JSON.parse(code);
        return "home";
    }






}