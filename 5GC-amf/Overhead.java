import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.logging.Logger;

public class Overhead {
    static final Logger logger = Logger.getLogger(Overhead.class.getName());
    private static Field z;
    private static Pairing pairing;

    public Overhead() {
        PairingFactory.getInstance().setUsePBCWhenPossible(true);
        pairing = PairingFactory.getPairing("a128.properties");
        z = pairing.getZr();
    }

    public void run() {
        int i, times = 1000;


        long start, end;
        double t;

        Element x = pairing.getG1().newRandomElement().getImmutable(),
                y = pairing.getG2().newRandomElement().getImmutable();
        start = System.nanoTime();
        for(i = 0; i < times; i++) {
            pairing.pairing(x, y);
        }
        end = System.nanoTime();
        t = (end - start)/1e6/ times;
        logger.info(String.format("Average pairing time => %sms", t));

        x = z.newRandomElement().getImmutable();
        start = System.nanoTime();
        for(i = 0; i < times; i++) {
            x.mulZn(x);
        }
        end = System.nanoTime();
        t = (end - start)/1e6/ times;
        logger.info(String.format("Average mul time => %sms", t));

        start = System.nanoTime();
        for(i = 0; i < times; i++) {
            x.powZn(x);
        }
        end = System.nanoTime();
        t = (end - start)/1e6/ times;
        logger.info(String.format("Average exp time => %sms", t));

        start = System.nanoTime();
        for(i = 0; i < times; i++) {
            x.powZn(x);
        }
        end = System.nanoTime();
        t = (end - start)/1e6/ times;
        logger.info(String.format("Average hash time => %sms", t));

        start = System.nanoTime();
        for(i = 0; i < times; i++) {
            x.powZn(x);
        }
        end = System.nanoTime();
        t = (end - start)/1e6/ times;
        logger.info(String.format("Average hmac time => %sms", t));

        start = System.nanoTime();
        for(i = 0; i < times; i++) {
            x.powZn(x);
        }
        end = System.nanoTime();
        t = (end - start)/1e6/ times;
        logger.info(String.format("Average encrypt time => %sms", t));
    }

    public static void main(String[] args) {
        Overhead o = new Overhead();
        o.run();
    }
}
