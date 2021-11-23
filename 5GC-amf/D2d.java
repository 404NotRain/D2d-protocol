import com.google.common.primitives.Bytes;

import java.io.*;
import java.math.BigInteger;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.logging.Logger;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;


public class D2d {
    static final Logger logger = Logger.getLogger(D2d.class.getName());
    private static byte[] IDs = "SSSSSSSSSSSSSSSS".getBytes();
    private static byte[] IDi = "IIIIIIIISSSSSSSS".getBytes();
    private static byte[] IDt = "TTTTTTTTSSSSSSSS".getBytes();
    private static byte[] Kold = "oldkoldkoldkoldk".getBytes();
    private static final String AMF_IP = "192.168.1.107";
    private static final int AMF_PORT = 4000;
    private static Socket socket;
    private static Pairing pairing;
    private static Field z;
    private IvParameterSpec ivspec = new IvParameterSpec(new byte[16]);

    public D2d() {
        //TypeACurveGenerator pg = new TypeACurveGenerator(128, 512);
        //PairingParameters typeAParams = pg.generate();
        //Pairing pairing = PairingFactory.getPairing(typeAParams);

        PairingFactory.getInstance().setUsePBCWhenPossible(true);
        pairing = PairingFactory.getPairing("a128.properties");
        z = pairing.getZr();
    }

    public static void main(String[] args) throws Exception {
        D2d d2d = new D2d();
        d2d.go();
    }

    public void go() throws IOException {
        System.out.print("Input your identity(S/I/T/O):");
        BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
        String identity = reader.readLine();
        switch (identity) {
            case "S" :
                (new SourceWorker()).start();
                break;
            case "I":
                (new InterWorker()).start();
                break;
            case "T":
                (new TargetWorker()).start();
                break;
            case "O":
                (new OverheadWorker()).start();
                break;
            default:
                logger.info("identity error");
        }
    }

    class SourceWorker extends Thread {
        static final String TAG = "SourceWorker";
        public void run() {
            int num;
            Element us = z.newRandomElement().getImmutable(),
                    cvalue = z.newRandomElement().getImmutable(),
                    count,
                    Tgn, n;
            logger.info( "You are UEs");

            byte[] t1 = new byte[16], t2 = new byte[16];
            byte[] m = "mmmmmmmmmmmm".getBytes();
            byte[] buffer = new byte[2048];

            try {
                //1. session config
                socket = new Socket(AMF_IP, AMF_PORT);
                OutputStream output = socket.getOutputStream();
                InputStream input = socket.getInputStream();
                output.write("S".getBytes());

                long start = System.nanoTime();
                new SecureRandom().nextBytes(t1);
                output.write(Bytes.concat(IDs, IDt, t1));

                num = input.read(buffer);
                if (num != 48) {
                    logger.info( "error => sid n Tg(n)");
                    return;
                }
                byte[] sid = Arrays.copyOfRange(buffer, 0, 16);
                n = z.newElementFromBytes(Arrays.copyOfRange(buffer, 16, 32)).getImmutable();
                Tgn = z.newElementFromBytes(Arrays.copyOfRange(buffer, 32, 48)).getImmutable();

                long s_tmp = System.nanoTime();
                Element Tus_n = T(us, n);
                long e_tmp = System.nanoTime();
                double t_tmp = (e_tmp - s_tmp)/1e6;
                logger.info( String.format("T(us,n) cost time => %sms", t_tmp));

                output.write(Bytes.concat(sid, Tus_n.toBytes()));
                logger.info( "step1 finished");

                //2. data transmit
                new SecureRandom().nextBytes(t2);

                byte[] TID = byteArrayXor(IDs, IDt, 16);
                TID = byteArrayXor(TID, n.toBytes(), 16);
                byte[] CID = byteArrayXor(IDs, cvalue.toBytes(), 16);
                count = cvalue.add(z.newOneElement().getImmutable());

                byte[] Knew = byteArrayXor(Kold, t2, 16);
                Cipher cipher = Cipher.getInstance("AES/CFB8/NoPadding");
                cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(Knew, "AES"), ivspec);
                byte[] beta = cipher.doFinal(t2);

                byte[] TS = ByteBuffer.allocate(4).putInt((int) (System.currentTimeMillis() / 1000)).array();

                cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(Kold, "AES"), ivspec);
                byte[] EM = cipher.doFinal(Bytes.concat(TS, t1, t2, m, beta ));

                Mac mac = Mac.getInstance("HmacMD5");
                mac.init(new SecretKeySpec(Kold, "RawBytes"));
                byte[] delta_m = mac.doFinal(Bytes.concat(sid, TID, EM));
                byte[] data = Bytes.concat(EM, delta_m);

                byte[] r1 = Tus_n.toBytes();

                s_tmp = System.nanoTime();
                Element Tus_tgn = T(us, Tgn);
                e_tmp = System.nanoTime();
                t_tmp = (e_tmp - s_tmp)/1e6;
                logger.info( String.format("T(us,tgn) cost time => %sms", t_tmp));

                cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(Tus_tgn.toBytes(), "AES"), ivspec);
                byte[] e1 =  cipher.doFinal(t1);
                mac.init(new SecretKeySpec(Tus_tgn.toBytes(), "RawBytes"));
                byte[] delta_1 = mac.doFinal(Bytes.concat(r1, e1));
                byte[] R1 = Bytes.concat(r1, e1, delta_1);

                mac.init(new SecretKeySpec(n.toBytes(), "RawBytes"));
                byte[] delta_T = mac.doFinal((Bytes.concat(sid, TID, CID, count.toBytes(), data, R1)));
                byte[] msg = Bytes.concat(sid, TID, CID, count.toBytes(), data, R1, delta_T);

                DatagramSocket udp_socket = new DatagramSocket();
                udp_socket.setBroadcast(true);
                udp_socket.send(new DatagramPacket(msg, msg.length, InetAddress.getByName("255.255.255.255"), 4001));
                logger.info( "step2 finished ");

                //3. session confirm
                num = input.read(buffer);
                if (num != 32) {
                    logger.info( "error => sid delta_c)");
                    return;
                }
                byte[] delta_ct = Arrays.copyOfRange(buffer, 16, 32);
                mac.init(new SecretKeySpec(Knew, "RawBytes"));
                byte[] delta_c = mac.doFinal(sid);

                if(!Arrays.equals(delta_c, delta_ct)) {
                    logger.info( "not matched delta_c");
                    return;
                }
                logger.info( "step3 finished");
                long end = System.nanoTime();
                double t = (end-start)/1e6;
                logger.info(String.format("Total time for protocol => %sms", t));

            } catch (Exception e) {
                logger.info( e.toString());
                return;
            }
        }
    }

    class InterWorker extends Thread {
        static final String TAG = "InterWorker";
        public void run() {
            int num;
            byte[] buffer = new byte[2048];
            Element ui = z.newRandomElement().getImmutable(),
                    Tgn, n;
            DatagramSocket serverSocket = null;
            logger.info( "You are UEi");

            try {
                //1. session config
                socket = new Socket(AMF_IP, AMF_PORT);
                OutputStream output = socket.getOutputStream();
                InputStream input = socket.getInputStream();
                output.write("I".getBytes());

                num = input.read(buffer);
                if (num != 48) {
                    logger.info( "error => sid n Tg(n)");
                    return;
                }
                byte[] sid = Arrays.copyOfRange(buffer, 0, 16);
                n = z.newElementFromBytes(Arrays.copyOfRange(buffer, 16, 32)).getImmutable();
                Tgn = z.newElementFromBytes(Arrays.copyOfRange(buffer, 32, 48)).getImmutable();

                long s_tmp = System.nanoTime();
                Element Tui_n = T(ui, n);
                long e_tmp = System.nanoTime();
                double t_tmp = (e_tmp - s_tmp)/1e6;
                logger.info( String.format("T(ui,n) cost time => %sms", t_tmp));

                output.write(Bytes.concat(sid, Tui_n.toBytes()));
                logger.info( "step1 finished");

                //2. data transmit
                serverSocket = new DatagramSocket(4001);
                serverSocket.setSoTimeout(4000);
                DatagramPacket receivePacket = new DatagramPacket(buffer,buffer.length);
                serverSocket.receive(receivePacket);

                byte[] sid_s = Arrays.copyOfRange(buffer, 0, 16);
                byte[] TID_s = Arrays.copyOfRange(buffer, 16, 32);
                byte[] CID_s = Arrays.copyOfRange(buffer, 32, 48);
                Element count = z.newElementFromBytes(Arrays.copyOfRange(buffer, 48, 64));
                count.add(z.newOneElement());

                byte[] data = Arrays.copyOfRange(buffer, 64, receivePacket.getLength()-64);
                byte[] R1_s = Arrays.copyOfRange(buffer, receivePacket.getLength()-64,
                        receivePacket.getLength()-16);
                byte[] delta_Ts = Arrays.copyOfRange(buffer, receivePacket.getLength()-16,
                        receivePacket.getLength());

                if(!Arrays.equals(sid, sid_s)) {
                    logger.info( "not matched sid");
                    return;
                }

                Mac mac = Mac.getInstance("HmacMD5");
                mac.init(new SecretKeySpec(n.toBytes(), "RawBytes"));
                byte[] delta_Ti = mac.doFinal(Arrays.copyOfRange(buffer, 0, receivePacket.getLength() - 16));
                if(!Arrays.equals(delta_Ti, delta_Ts)) {
                    logger.info( "not matched delta t");
                    return;
                }


                byte[] r2 = Tui_n.toBytes();
                Cipher cipher = Cipher.getInstance("AES/CFB8/NoPadding");

                s_tmp = System.nanoTime();
                Element Tui_tgn = T(ui, Tgn);
                e_tmp = System.nanoTime();
                t_tmp = (e_tmp - s_tmp)/1e6;
                logger.info( String.format("T(ui,Tgn) cost time => %sms", t_tmp));

                cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(Tui_tgn.toBytes(), "AES"), ivspec);
                byte[] e2 =  cipher.doFinal(Arrays.copyOfRange(R1_s, 16, 32));
                mac.init(new SecretKeySpec(Tui_tgn.toBytes(), "RawBytes"));
                byte[] delta_2 = mac.doFinal(Bytes.concat(r2, e2));
                byte[] R2 = Bytes.concat(r2, e2, delta_2);

                byte[] R = Bytes.concat(R1_s, R2);
                mac.init(new SecretKeySpec(n.toBytes(), "RawBytes"));
                byte[] delta_T = mac.doFinal((Bytes.concat(sid_s, TID_s, CID_s, count.toBytes(), data, R)));
                byte[] msg = Bytes.concat(sid_s, TID_s, CID_s, count.toBytes(), data, R, delta_T);

                DatagramSocket udp_socket = new DatagramSocket();
                udp_socket.setBroadcast(true);
                udp_socket.send(new DatagramPacket(msg, msg.length, InetAddress.getByName("255.255.255.255"), 4002));

                logger.info( "step2 finished");

            } catch (Exception e) {
                logger.info( e.toString());
            }
            finally {
                if(serverSocket != null) {
                    serverSocket.close();
                }
            }
        }
    }

    class TargetWorker extends Thread {
        static final String TAG = "TargetWorker";
        public void run() {
            int num;
            byte[] buffer = new byte[2048];
            Element ut = z.newRandomElement().getImmutable(),
                    Tgn, n;
            DatagramSocket serverSocket = null;
            logger.info( "You are UEt");

            try {
                //1. session config
                socket = new Socket(AMF_IP, AMF_PORT);
                OutputStream output = socket.getOutputStream();
                InputStream input = socket.getInputStream();
                output.write("T".getBytes());

                num = input.read(buffer);
                if (num != 80) {
                    logger.info( "error => sid n Tg(n) IDs t1");
                    return;
                }

                byte[] sid = Arrays.copyOfRange(buffer, 0, 16);
                n = z.newElementFromBytes(Arrays.copyOfRange(buffer, 16, 32)).getImmutable();
                Tgn = z.newElementFromBytes(Arrays.copyOfRange(buffer, 32, 48)).getImmutable();
                //byte[] IDs = Arrays.copyOfRange(buffer, 48, 64);
                byte[] t1 = Arrays.copyOfRange(buffer, 64, 80);
                logger.info( "step1 finished");


                //2. data transmit
                serverSocket = new DatagramSocket(4002);
                serverSocket.setSoTimeout(4000);
                DatagramPacket receivePacket = new DatagramPacket(buffer,buffer.length);
                serverSocket.receive(receivePacket);

                byte[] sid_s = Arrays.copyOfRange(buffer, 0, 16);
                byte[] TID_s = Arrays.copyOfRange(buffer, 16, 32);
                byte[] CID_s = Arrays.copyOfRange(buffer, 32, 48);
                Element count = z.newElementFromBytes(Arrays.copyOfRange(buffer, 48, 64));

                byte[] data = Arrays.copyOfRange(buffer, 64, receivePacket.getLength()-112);
                byte[] R1_s = Arrays.copyOfRange(buffer, receivePacket.getLength()-112,
                        receivePacket.getLength()-16);
                byte[] delta_Ts = Arrays.copyOfRange(buffer, receivePacket.getLength()-16,
                        receivePacket.getLength());

                if(!Arrays.equals(sid, sid_s)) {
                    logger.info( "not matched sid");
                    return;
                }

                Mac mac = Mac.getInstance("HmacMD5");
                mac.init(new SecretKeySpec(n.toBytes(), "RawBytes"));
                byte[] delta_Tt = mac.doFinal(Arrays.copyOfRange(buffer, 0, receivePacket.getLength() - 16));
                if(!Arrays.equals(delta_Tt, delta_Ts)) {
                    logger.info( "not matched delta t");
                    return;
                }

                byte[] IDs_t = byteArrayXor(TID_s, IDt, 16);
                IDs_t = byteArrayXor(IDs_t, n.toBytes(), 16);
                if(!Arrays.equals(IDs_t, IDs)) {
                    logger.info( "not matched IDs");
                    return;
                }

                Element cvalue = z.newElementFromBytes(byteArrayXor(CID_s, IDs, 16));
                if(! count.sub(cvalue).isEqual(z.newElement(R1_s.length / 48))) {
                    logger.info( "not matched track length");
                    return;
                }

                byte[] EM = Arrays.copyOfRange(data, 0, data.length-16);
                mac.init(new SecretKeySpec(Kold, "RawBytes"));
                byte[] delta_mt = mac.doFinal(Bytes.concat(sid_s, TID_s, EM));
                if(!Arrays.equals(delta_mt, Arrays.copyOfRange(data,  data.length-16, data.length))) {
                    logger.info( "not matched delta_m");
                    return;
                }

                Cipher cipher = Cipher.getInstance("AES/CFB8/NoPadding");
                cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(Kold, "AES"), ivspec);
                byte[] DM =  cipher.doFinal(EM);
                byte[] TS_t = Arrays.copyOfRange(DM, 0, 4);
                byte[] t1_t = Arrays.copyOfRange(DM, 4, 20);
                byte[] t2_t = Arrays.copyOfRange(DM, 20, 36);
                //byte[] m_t = Arrays.copyOfRange(DM, 36, DM.length-16);
                byte[] beta_t = Arrays.copyOfRange(DM, DM.length-16, DM.length);
                if(!Arrays.equals(t1_t, t1)) {
                    logger.info( "not matched t1");
                    return;
                }

                byte[] Knew = byteArrayXor(Kold, t2_t, 16);
                cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(Knew, "AES"), ivspec);
                byte[] beta_tt =  cipher.doFinal(t2_t);
                if(!Arrays.equals(beta_tt, beta_t)) {
                    logger.info( "not matched beta");
                    return;
                }
                logger.info( "step2 finished");

                //3. session confirm
                mac.init(new SecretKeySpec(Knew, "RawBytes"));
                byte[] delta_c = mac.doFinal(sid);
                output.write(Bytes.concat(sid, delta_c, R1_s));
                logger.info( "step3 finished");

            } catch (Exception e) {
                logger.info( e.toString());
            }
            finally {
                if(serverSocket != null) {
                    serverSocket.close();
                }
            }
        }
    }

    class OverheadWorker extends Thread  {
        static final String TAG = "OverheadWorker";

        public void run() {
            int i, times = 1000;
            long start, end;
            double t;

            byte[] IK = new byte[16];
            byte[] CK = new byte[16];
            byte[] plain = new byte[160];
            (new SecureRandom()).nextBytes(IK);
            (new SecureRandom()).nextBytes(CK);
            (new SecureRandom()).nextBytes(plain);

            Element x = pairing.getG1().newRandomElement().getImmutable(),
                    y = pairing.getG2().newRandomElement().getImmutable();
            start = System.nanoTime();
            for (i = 0; i < times; i++) {
                pairing.pairing(x, y);
            }
            end = System.nanoTime();
            t = (end - start) / 1e6 / times;
            logger.info(String.format("Average pairing time => %sms", t));

            x = z.newRandomElement().getImmutable();
            y = z.newRandomElement().getImmutable();
            start = System.nanoTime();
            for (i = 0; i < times; i++) {
                x.mulZn(y);
            }
            end = System.nanoTime();
            t = (end - start) / 1e6 / times;
            logger.info(String.format("Average mul time => %sms", t));

            start = System.nanoTime();
            for (i = 0; i < times; i++) {
                x.powZn(y);
            }
            end = System.nanoTime();
            t = (end - start) / 1e6 / times;
            logger.info(String.format("Average exp time => %sms", t));

            start = System.nanoTime();
            for (i = 0; i < times; i++) {
                z.newElementFromHash(plain, 0, 16);
            }
            end = System.nanoTime();
            t = (end - start) / 1e6 / times;
            logger.info(String.format("Average hash time => %sms", t));

            try {
                Mac mac = Mac.getInstance("HmacMD5");
                mac.init(new SecretKeySpec(IK, "RawBytes"));
                start = System.nanoTime();
                for (i = 0; i < times; i++) {
                    mac.doFinal(plain);
                }
                end = System.nanoTime();
                t = (end - start) / 1e6 / times;
                logger.info(String.format("Average hmac time => %sms", t));


                Cipher cipher = Cipher.getInstance("AES/CFB8/NoPadding");
                cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(CK, "AES"), ivspec);
                start = System.nanoTime();
                for (i = 0; i < times; i++) {
                    cipher.doFinal(plain);
                }
                end = System.nanoTime();
                t = (end - start) / 1e6 / times;
                logger.info(String.format("Average encrypt time => %sms", t));
            } catch (Exception e) {
                logger.info(e.toString());
            }
        }
    }

    private Element T(Element p, Element x) {
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

    private byte[] byteArrayXor(byte[] a1, byte[] a2, int len) {
        byte[] result = new byte[len];
        for(int i = 0; i < len; i++) {
            result[i] = (byte) (a1[i] ^ a2[i]);
        }
        return result;
    }

}


