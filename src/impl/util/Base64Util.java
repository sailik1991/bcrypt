package impl.util;

public class Base64Util {
  // Lookup for Base64 encoding
  static private final String I_TO_A64 =
      "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

  // Table for Base64 decoding
  static private final byte index_64[] = {-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
      -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
      -1, -1, -1, -1, -1, -1, -1, -1, -1, 0, 1, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, -1, -1, -1,
      -1, -1, -1, -1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
      23, 24, 25, 26, 27, -1, -1, -1, -1, -1, -1, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39,
      40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, -1, -1, -1, -1, -1};

  /**
   * Encode a byte array using base64 defined in bcypt's original implementation. Ref:
   * http://mail-index.netbsd.org/tech-crypto/2002/05/24/msg000204.htm
   *
   * @param input
   * @param bytesToBeEncoded
   * @return base64-encoded
   * @exception IllegalArgumentException
   */
  public String encode(byte input[], int bytesToBeEncoded) throws IllegalArgumentException {

    // Have a check on length to make sure buffer overflow attacks can be prevented on the
    // memory space when calling the encode function.
    if (bytesToBeEncoded <= 0 || bytesToBeEncoded > input.length)
      throw new IllegalArgumentException("Exception occured while encoding.");

    StringBuffer output = new StringBuffer();
    int c1, c2, i = 0;

    while (true) {

      // The initial XOR-ing makes sure we dont get land up with a negative value since we are using
      // c1 and c2 as ints
      c1 = input[i++] & 0xff;
      output.append(I_TO_A64.charAt(c1 >> 2));
      c1 = (c1 & 0x03) << 4;

      if (i >= bytesToBeEncoded) {
        output.append(I_TO_A64.charAt(c1));
        break;
      }

      c2 = input[i++] & 0xff;
      // The following mask is just a verification check to ensure that the first 4 bits are unset.
      // This is fail safe even in systems where left rotation can result in 1 bits to the left.
      // It can also prevent against attacks in such machines.
      // Ref: http://goo.gl/xGHqL1
      c1 |= (c2 >> 4) & 0x0f;
      output.append(I_TO_A64.charAt(c1));
      c1 = (c2 & 0x0f) << 2;

      if (i >= bytesToBeEncoded) {
        output.append(I_TO_A64.charAt(c1 & 0x3f));
        break;
      }

      c2 = input[i++] & 0xff;
      c1 |= (c2 >> 6) & 0x03;
      output.append(I_TO_A64.charAt(c1));
      output.append(I_TO_A64.charAt(c2 & 0x3f));
    }
    return output.toString();
  }

  /**
   * Look up the 3 bits of the base64-encoded value corresponding to the specified character.
   * 
   * @param x the base64-encoded value
   * @return the decoded value of x
   */
  private byte char64(char x) {
    if ((int) x < 0 || (int) x > index_64.length)
      return -1;
    return index_64[(int) x];
  }

  /**
   * Decode a string using base64 defined in bcypt's original implementation. Ref:
   * http://mail-index.netbsd.org/tech-crypto/2002/05/24/msg000204.htm
   * 
   * @param input
   * @param bytesToBeDecoded
   * @return decoded bytes array
   * @throws IllegalArgumentException
   */
  public byte[] decode(String input, int bytesToBeDecoded) throws IllegalArgumentException {

    if (bytesToBeDecoded <= 0 || bytesToBeDecoded > input.length())
      throw new IllegalArgumentException("Exception occured while decoding.");

    StringBuffer buffer = new StringBuffer();
    int i = 0, buffer_length = 0;
    byte c1, c2, c3, c4;

    while (i < input.length() - 1 && buffer_length < bytesToBeDecoded) {
      c1 = char64(input.charAt(i++));
      c2 = char64(input.charAt(i++));

      // Invalid data checking
      if (c1 == -1 || c2 == -1)
        break;

      buffer.append((char) ((byte) (c1 << 2) | (c2 & 0x30) >> 4));
      if (++buffer_length >= bytesToBeDecoded || i >= input.length())
        break;

      c3 = char64(input.charAt(i++));
      if (c3 == -1)
        break;

      buffer.append((char) ((byte) ((c2 & 0x0f) << 4) | (c3 & 0x3c) >> 2));
      if (++buffer_length >= bytesToBeDecoded || i >= input.length())
        break;

      c4 = char64(input.charAt(i++));
      buffer.append((char) ((byte) ((c3 & 0x03) << 6) | c4));
      ++buffer_length;
    }

    byte output[] = new byte[buffer_length];
    for (i = 0; i < buffer_length; i++) {
      output[i] = (byte) buffer.charAt(i);
    }
    return output;
  }
}
