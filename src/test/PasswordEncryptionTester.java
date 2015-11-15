package test;

import impl.BCrypt;
import impl.BCryptImpl;

public class PasswordEncryptionTester {
  public static void main(String args[]) {
    BCryptImpl b = new BCryptImpl();    
    
    System.out.println("================================================================");
    System.out.println(b.bcryptHash("abcdefghijklmnopqrstuvwxyz", "$2a$06$.rCVZVOThsIa97pEDOxvGu"));
    System.out.println(BCrypt.hashpw("abcdefghijklmnopqrstuvwxyz", "$2a$06$.rCVZVOThsIa97pEDOxvGu"));    
    System.out.println("$2a$06$.rCVZVOThsIa97pEDOxvGuRRgzG64bvtJ0938xuqzv18d3ZpQhstC");
    System.out.println("================================================================");
    
    System.out.println("================================================================");
    System.out.println(b.bcryptHash("abc", "$2a$12$EXRkfkdmXn2gzds2SSitu."));
    System.out.println(BCrypt.hashpw("abc", "$2a$12$EXRkfkdmXn2gzds2SSitu."));
    System.out.println("$2a$12$EXRkfkdmXn2gzds2SSitu.MW9.gAVqa9eLS1//RYtYCmB1eLHg.9q");
    System.out.println("================================================================");
  }
}
