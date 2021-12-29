import com.google.common.primitives.Bytes;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

public class Amf {
    static final Logger logger = Logger.getLogger(Amf.class.getName());

	private final int PORT = 40000;
	private final ServerSocket serverSocket;
	private final Map<String, Socket> socketMaps;
	private Element g;
	private Field z;

	public Amf() throws Exception {
		serverSocket = new ServerSocket(PORT);
		socketMaps = new HashMap<>();

		//TypeACurveGenerator pg = new TypeACurveGenerator(128, 512);
		//PairingParameters typeAParams = pg.generate();
		PairingFactory.getInstance().setUsePBCWhenPossible(true);
		//Pairing pairing = PairingFactory.getPairing(typeAParams);
		Pairing pairing = PairingFactory.getPairing("a128.properties");

		z = pairing.getZr();
		g = z.newRandomElement().getImmutable();
	}

	public void run() throws Exception {
        byte[] buffer = new byte[2048];
        byte[] sid = new byte[16];
        int count;
        Element n;

        n = z.newRandomElement().getImmutable();
        new SecureRandom().nextBytes(sid);
        socketMaps.clear();
        logger.info("Amf start");
        Element Tg_n = T(g, n);


		while (true) {
			Socket clientSocket = serverSocket.accept();

			count = clientSocket.getInputStream().read(buffer);
            if (count != 1) {
                logger.log(Level.WARNING ,"Wrong Identity");
                return;
            }
			socketMaps.put(new String(buffer, 0, 1), clientSocket);
			logger.log(Level.INFO, () ->
					String.format("Receive a hello from => %s", new String(buffer, 0, 1)));

			if (socketMaps.containsKey("S") && socketMaps.containsKey("R") && //) {
					socketMaps.containsKey("T")) {
				break;
			}
		}

		count = socketMaps.get("S").getInputStream().read(buffer);
		if (count != 48) {
            logger.log(Level.WARNING ,"[error]: IDs IDt t1");
			return;
		}

		byte[] IDs = Arrays.copyOfRange(buffer, 0, 16);
        byte[] IDt = Arrays.copyOfRange(buffer, 16, 32);
        byte[] t1 = Arrays.copyOfRange(buffer, 32, 48);

		socketMaps.get("T").getOutputStream().write(Bytes.concat(sid, n.toBytes(),
				Tg_n.toBytes(), IDs, t1));

		logger.log(Level.INFO, () -> "Write secret to TargetWorker");

		socketMaps.get("S").getOutputStream().write(Bytes.concat(sid, n.toBytes(),
				Tg_n.toBytes()));
		logger.log(Level.INFO, () -> "Write secret to SourceWorker");
		count = socketMaps.get("S").getInputStream().read(buffer);
		if (count != 32) {
            logger.log(Level.WARNING ,"Step 4.1 failed");
			return;
		}

		socketMaps.get("R").getOutputStream().write(Bytes.concat(sid, n.toBytes(),
				Tg_n.toBytes()));
		logger.log(Level.INFO, () -> "Write secret to RelayWorker");
		count = socketMaps.get("R").getInputStream().read(buffer);
		if (count != 32) {
            logger.log(Level.WARNING ,"Step 4.2 failed");
			return;
		}

        count = socketMaps.get("T").getInputStream().read(buffer);
        if (count != 128) {
            logger.log(Level.WARNING ,"session confirm failed");
            return;
        }
        socketMaps.get("S").getOutputStream().write(buffer, 0, 32);
		logger.log(Level.INFO ,"session confirm succeed");

	}

	private Element T(Element p, Element x) {
		//long start = System.nanoTime();

		Element[][] A =  { {z.newZeroElement().getImmutable(), z.newOneElement().getImmutable()},
				{z.newOneElement().negate().getImmutable(), x.mul(2).getImmutable()}};
		Element[][] Ap = { {z.newZeroElement().getImmutable(), z.newOneElement().getImmutable()},
				{z.newOneElement().negate().getImmutable(), x.mul(2).getImmutable()}};
		BigInteger bp = p.toBigInteger();

		for(int i = bp.bitLength() - 1; i > 0; i--) {
			Ap = matmul(Ap, Ap);
			if(bp.testBit(i-1)) {
				Ap = matmul(Ap, A);
			}
		}
		//long end = System.nanoTime();
		//double t = (end-start)/1e6;
		//logger.info( String.format("Test time for T(%s, %s) => %sms", p, x, t));
		return Ap[0][0].mul(z.newOneElement()).add(Ap[0][1].mul(x));
	}

	private static Element[][] matmul(Element m1[][], Element m2[][]) {
		Element[][] result = new Element[2][2];
		for(int i = 0; i < 2; i++)
			for(int j = 0; j < 2; j++){
				result[i][j] = m1[i][0].mul(m2[0][j]).add(m1[i][1].mul(m2[1][j]));
			}
		return result;
	}


    public static void main(String[] args) throws Exception {
        Amf amf = new Amf();
        while(true) {
            amf.run();
        }
    }

    private int testT(int p, int x) {
		if(p == 0) {
			return 1;
		}
		else if(p == 1) {
			return x;
		}
		else {
			return 2*x*testT(p-1, x) - testT(p-2, x);
		}
	}

}


