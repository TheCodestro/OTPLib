/*******************************************************************************
 * Copyright (c) 2015, The Codestro
 * All rights reserved.
 *
 * This product is licensed under the BSD 3-Clause "New" or "Revised" License.
 * For more information see http://opensource.org/licenses/BSD-3-Clause or
 * the included LICENSE file.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *******************************************************************************/
/**
 * 
 */
package ninja.thecodestro.otplib;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * @author Brian
 *
 */
public class OTP {

	/**
	 * @param hmacKey
	 *            bytes used for the key
	 * @param authTxt
	 *            the thing being checked
	 * @return returns an SHA1 hashed version of the given text based on hmacKey
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 */

	public static
			byte[]
			genHMAC(byte[] hmacKey, byte[] authTxt)
													throws NoSuchAlgorithmException,
													InvalidKeyException {
		Mac theHMAC;
		try {
			theHMAC = Mac.getInstance("HmacSHA1");
		} catch (NoSuchAlgorithmException nsax) {
			theHMAC = Mac.getInstance("HMAC-SHA-1");
			System.console().printf(null, "System uses HMAC-SHA-1");
		}
		SecretKeySpec spec_hmacKey = new SecretKeySpec(hmacKey, "RAW");
		theHMAC.init(spec_hmacKey);
		return theHMAC.doFinal(authTxt);
	}

	private static byte[] genLongOTP(long theCounter) {
		byte[] longOTP = new byte[8];
		for (int i = longOTP.length - 1; i >= 0; i--) {
			longOTP[i] = (byte) (theCounter & 0b11111111);
			theCounter >>= 8;
		}
		return longOTP;
	}

	private static final int[] BIN_POWERS = { 1, 10, 100, 1000, 10000, 100000,
			1000000, 10000000, 100000000 };

	/**
	 * @param theSecret
	 *            secret key
	 * @param theCounter
	 *            how much to move things
	 * @param numDigOTP
	 *            desired length of OTP
	 * @param truncateLoc
	 *            where to get the OTP from
	 * @return theOTP -- finalized OTP
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 */

	public static String
			genOTP(byte[] theSecret, long theCounter, int numDigOTP,
					int truncateLoc) throws NoSuchAlgorithmException,
									InvalidKeyException {
		// This is what will be returned
		String theOTP = null;

		byte[] b_theOTP = new byte[8];
		b_theOTP = genLongOTP(theCounter);

		// make the HMAC!
		byte[] theHash = genHMAC(theSecret, b_theOTP);

		int offset = theHash[theHash.length - 1] & 0xf;
		if ((0 <= truncateLoc) && (truncateLoc < (theHash.length - 4))) {
			offset = truncateLoc;
		}

		int bin_theHash = ((theHash[offset] & 0x7f) << 24)
				| ((theHash[offset + 1] & 0xff) << 16)
				| ((theHash[offset + 2] & 0xff) << 8)
				| (theHash[offset + 3] & 0xff);

		int int_theOTP = bin_theHash % BIN_POWERS[numDigOTP];
		theOTP = Integer.toString(int_theOTP);
		// Make sure it's long enough, if not, add numbers to it until it is
		while (theOTP.length() < numDigOTP) {
			theOTP = "0" + theOTP;
		}
		return theOTP;
	}

	/**
	 * This is for debugging only
	 * 
	 * @param args
	 *            should be the pass to encode
	 */

	public static void main(String[] args) {
		Long theCounter = (long) 10;
		if (args.length > 0) {
			try {
				if (args[1] == "totp") {
					theCounter = System.currentTimeMillis();
					System.out.println("Using TOTP");
				} else {
					System.out.println("Using HOTP");
				}
			} catch (ArrayIndexOutOfBoundsException aibe) {
				System.out.println("You must specify hotp or totp");
			} finally {
				byte[] b_thePass = args[0].getBytes();

				for (int i = 0; i < 10; i++) {
					System.out.println("i = " + i);
					try {
						// TODO fix the keys always being the same given
						// different times
						String outputString = Arrays.toString(OTP.genHMAC(
								b_thePass, OTP.genLongOTP(theCounter)));
						System.out.println("HMAC: "
 + outputString);
					} catch (InvalidKeyException e1) {
						e1.printStackTrace();
					} catch (NoSuchAlgorithmException e1) {
						e1.printStackTrace();
					}
					try {
						System.out.println("OTP: "
								+ OTP.genOTP(b_thePass, theCounter, 6, i));
					} catch (Exception e) {
						e.printStackTrace();
					}
				}
			}
		} else {
			System.out.println("Requires entry of the pass in commandline.");
		}
	}
}
