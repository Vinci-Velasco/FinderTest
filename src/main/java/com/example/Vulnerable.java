package com.example;

import java.util.Scanner;

// command line injection vulnerable class
public class Vulnerable {
    public static void main(String[] args) throws Exception {
        Scanner myObj = new Scanner(System.in);
        // potential source
        String userInput = myObj.nextLine();
        String cmd = "./mytool --version " + userInput;

        String userArg = args[0];

        // potential sinks
        Runtime.getRuntime().exec(cmd);
        Runtime.getRuntime().exec("mytool arg1 arg2");
        Runtime.getRuntime().exec("mytool arg1 arg2 " + userArg);
    }
}
