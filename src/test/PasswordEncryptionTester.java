package test;

import impl.BCrypt;
import impl.BCryptImpl;

public class PasswordEncryptionTester {
  public static void main(String args[]) {
    BCryptImpl b = new BCryptImpl();    
    System.out.println("================================================================");
    System.out.println("| " + b.hashPassword("sailik8331") + " |");
    System.out.println("================================================================");
  }
}
