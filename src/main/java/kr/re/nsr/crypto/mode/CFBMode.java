package kr.re.nsr.crypto.mode;

import static kr.re.nsr.crypto.util.Ops.*;
import kr.re.nsr.crypto.BlockCipher;
import kr.re.nsr.crypto.BlockCipher.Mode;
import kr.re.nsr.crypto.BlockCipherModeStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

// DONE: block vs buffer
public class CFBMode extends BlockCipherModeStream {
	private static final Logger log = LogManager.getLogger();

	private byte[] iv;
	private byte[] block;
	private byte[] feedback;

	public CFBMode(BlockCipher cipher) {
		super(cipher);
	}

	@Override
	public String getAlgorithmName() {
		return engine.getAlgorithmName() + "/CFB";
	}

	@Override
	public void init(Mode mode, byte[] mk, byte[] iv) {
		this.mode = mode;
		engine.init(Mode.ENCRYPT, mk);

		this.iv = iv.clone();
		block = new byte[blocksize];
		feedback = new byte[blocksize];
		reset();
	}

	@Override
	public void reset() {
		super.reset();
		System.arraycopy(iv, 0, feedback, 0, blocksize);
	}

	@Override
	protected int processBlock(byte[] in, int inOff, byte[] out, int outOff, int outlen) {
		int length = engine.processBlock(feedback, 0, block, 0);
		XOR(out, outOff, in, inOff, block, 0, outlen);

		log.debug("in size: {}", in.length);
		log.debug("inOff: {}", inOff);
		log.debug("out size: {}", out.length);
		log.debug("outOff: {}", outOff);
		log.debug("outlen: {}", outlen);
		log.debug("feedback size: {}", feedback.length);
		log.debug("blocksize: {}", blocksize);

		if (mode == Mode.ENCRYPT) {
			System.arraycopy(out, outOff, feedback, 0, blocksize);
		} else {
			System.arraycopy(in, inOff, feedback, 0, blocksize);
		}

		return length;
	}

}
