package impl;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

/**
 * 
 * Copyright (c) 2015 sailik1991 <link2sailik@gmail.com>
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software and
 * associated documentation files (the "Software"), to deal in the Software without restriction,
 * including without limitation the rights to use, copy, modify, merge, publish, distribute,
 * sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all copies or
 * substantial portions of the Software. THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY
 * KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
 * OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * INTHE SOFTWARE.
 *
 */
public class BCryptImplTest {

  /*
   * test_vectors[x][0] = password test_vectors[x][1] = random salt test_vectors[x][2] =
   * corresponding hash test_vectors obtained from Damien Miller
   */
  private String test_vectors[][] = {
      {"", "$2a$06$DCq7YPn5Rq63x1Lad4cll.",
          "$2a$06$DCq7YPn5Rq63x1Lad4cll.l8DCCJRUmhIHycj4PL.yqCqvB72lOgi"},
      {"", "$2a$08$HqWuK6/Ng6sg9gQzbLrgb.",
          "$2a$08$HqWuK6/Ng6sg9gQzbLrgb.YJMlxGj5..6aYOFVLx2I3gApLkrsqHy"},
      {"", "$2a$10$k1wbIrmNyFAPwPVPSVa/ze",
          "$2a$10$k1wbIrmNyFAPwPVPSVa/ze2vUlrK65aer9vJeUyCwoZ8LRukbixFy"},
      {"", "$2a$12$k42ZFHFWqBp3vWli.nIn8u",
          "$2a$12$k42ZFHFWqBp3vWli.nIn8uwTPllkc4whnT0DWpYumhuw5GRQjIoL2"},
      {"a", "$2a$06$m0CrhHm10qJ3lXRY.5zDGO",
          "$2a$06$m0CrhHm10qJ3lXRY.5zDGOck6NibcudrieM3GvWYCBEal.I7dWItK"},
      {"a", "$2a$08$cfcvVd2aQ8CMvoMpP2EBfe",
          "$2a$08$cfcvVd2aQ8CMvoMpP2EBfeeKnKv4ZugZyDK3FfNrJbyRks4N0xBBG"},
      {"a", "$2a$10$k87L/MF28Q673VKh8/cPi.",
          "$2a$10$k87L/MF28Q673VKh8/cPi.MYLeE/xbcqFIkFJiSKbkVidRb1WNDhG"},
      {"a", "$2a$12$8NJH3LsPrANStV6XtBakCe",
          "$2a$12$8NJH3LsPrANStV6XtBakCeKrtHTV37/.Y7YE6q5vEu9iztyr3ie9S"},
      {"abc", "$2a$06$If6bvum7DFjUnE9p2uDeDu",
          "$2a$06$If6bvum7DFjUnE9p2uDeDucdscf8wp/beE8dxpACPWPbQPQAnyf1O"},
      {"abc", "$2a$08$Ro0CUfOqk6cXEKf3dyaM7O",
          "$2a$08$Ro0CUfOqk6cXEKf3dyaM7OKMK.01c0u5QYoglbuhjxHBEBQMWRTVu"},
      {"abc", "$2a$10$WvvTPHKwdBJ3uk0Z37EMR.",
          "$2a$10$WvvTPHKwdBJ3uk0Z37EMR.EoaHtRg1Qiaq7PtybWBJLGYt1a3opUm"},
      {"abc", "$2a$12$EXRkfkdmXn2gzds2SSitu.",
          "$2a$12$EXRkfkdmXn2gzds2SSitu..NoIVUH9pVrRcoLY1rTJhZboTJU0o6a"},
      {"abcdefghijklmnopqrstuvwxyz", "$2a$06$.rCVZVOThsIa97pEDOxvGu",
          "$2a$06$.rCVZVOThsIa97pEDOxvGuGggGj8s4pHEW0dYrMaoS9pbQjH5Do/m"},
      {"abcdefghijklmnopqrstuvwxyz", "$2a$08$aTsUwsyowQuzRrDqFflhge",
          "$2a$08$aTsUwsyowQuzRrDqFflhge5KCdMs5Ef7WHdacYmEYichM1dJB9Kgq"},
      {"abcdefghijklmnopqrstuvwxyz", "$2a$10$fVH8e28OQRj9tqiDXs1e1u",
          "$2a$10$fVH8e28OQRj9tqiDXs1e1ueS3GoP5wCbudEwcC6awdgJ.KQN4PAjO"},
      {"abcdefghijklmnopqrstuvwxyz", "$2a$12$D4G5f18o7aMMfwasBL7Gpu",
          "$2a$12$D4G5f18o7aMMfwasBL7GpufJ29BNvJO961xwJsu86pbMpcss59YdS"},
      {"~!@#$%^&*()      ~!@#$%^&*()PNBFRD", "$2a$06$fPIsBO8qRqkjj273rfaOI.",
          "$2a$06$fPIsBO8qRqkjj273rfaOI..wj8PdutB5cGzvST8alqzqHVaDfhFI6"},
      {"~!@#$%^&*()      ~!@#$%^&*()PNBFRD", "$2a$08$Eq2r4G/76Wv39MzSX262hu",
          "$2a$08$Eq2r4G/76Wv39MzSX262huQLgU/XiFe7am/r8qxUDeIXor8rF5.HO"},
      {"~!@#$%^&*()      ~!@#$%^&*()PNBFRD", "$2a$10$LgfYWkbzEvQ4JakH7rOvHe",
          "$2a$10$LgfYWkbzEvQ4JakH7rOvHe/1l.1FHoFsG65KYkvRbMxzkceb2tZ4C"},
      {"~!@#$%^&*()      ~!@#$%^&*()PNBFRD", "$2a$12$WApznUOJfkEGSmYRfnkrPO",
          "$2a$12$WApznUOJfkEGSmYRfnkrPOpx0oiYA8mS1Xwg0tay8KTcb84v22MZi"}};

  private BCryptImpl bc = new BCryptImpl();

  @Test
  public void testBcryptHash() {
    for (int i = 0; i < test_vectors.length; i++) {
      String actual = bc.bcryptHash(test_vectors[i][0], test_vectors[i][1]);
      assertEquals(test_vectors[i][2], actual);
    }
  }

  @Test
  public void testBcryptCheck() {
    for (int i = 0; i < test_vectors.length; i++) {
      boolean actual = bc.bcryptCheck(test_vectors[i][0], test_vectors[i][2]);
      assertTrue(actual);
    }
  }

  @Test
  public void testGenerateSalt() {
    for (int i = 0; i < test_vectors.length; i+=5) {
      String hash1 = bc.bcryptHash(test_vectors[i][0], bc.generateSalt());
      String hash2 = bc.bcryptHash(test_vectors[i][0], hash1);
      assertEquals(hash1, hash2);
    }
  }
  
  @Test(expected=IllegalArgumentException.class)
  public void testWrongMajorVersion() {
    bc.bcryptCheck(test_vectors[0][0], "$3a$08$aTsUwsyowQuzRrDqFflhge");
  }
  
  @Test(expected=IllegalArgumentException.class)
  public void testWrongMinorVersion() {
    bc.bcryptCheck(test_vectors[0][0], "$2d$08$aTsUwsyowQuzRrDqFflhge");
  }
  
  @Test(expected=IllegalArgumentException.class)
  public void testRoundsBelowLowerLimit() {
    bc.bcryptCheck(test_vectors[0][0], "$2a$03$aTsUwsyowQuzRrDqFflhge");
  }
  
  @Test(expected=IllegalArgumentException.class)
  public void testRoundsAboveUpperLimit() {
    bc.bcryptCheck(test_vectors[0][0], "$2a$32$aTsUwsyowQuzRrDqFflhge");
  }
}
