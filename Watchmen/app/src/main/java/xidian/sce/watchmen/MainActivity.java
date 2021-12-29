package xidian.sce.watchmen;

import android.content.Context;
import android.os.Bundle;
import android.view.View;
import android.widget.Spinner;

import androidx.appcompat.app.AppCompatActivity;

import com.google.common.io.BaseEncoding;
import com.google.common.primitives.Bytes;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import xidian.sce.watchmen.logger.Log;
import xidian.sce.watchmen.logger.LogFragment;
import xidian.sce.watchmen.logger.LogWrapper;
import xidian.sce.watchmen.logger.MessageOnlyLogFilter;


public class MainActivity extends AppCompatActivity {
    private static final String TAG = "MainActivity";

    private static byte[] IDs = "SSSSSSSSSSSSSSSS".getBytes();
    private static byte[] IDr = "RRRRRRRRRRRRRRRR".getBytes();
    private static byte[] IDt = "TTTTTTTTTTTTTTTT".getBytes();
    private static byte[] Kold = "oldkoldkoldkoldk".getBytes(); // shared key between source and target
    private static byte[] Kold2 = "kdlokdlokdlokdlo".getBytes(); // shared key between relay and target

    private static final String AMF_IP = "192.168.0.103";
    private static final int AMF_PORT = 40000;
    private static Socket socket;

    private static Pairing pairing;
    private static Field z;
    private IvParameterSpec ivspec = new IvParameterSpec(new byte[16]);
    private static Element us, ur, ut;

    private Thread worker = null;
    private int relayMode = 0, sourceMode = 0, targetMode = 0;
    private String packetFile = "packet.txt";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        initializeLogging();

        //TypeACurveGenerator pg = new TypeACurveGenerator(128, 512);
        //PairingParameters typeAParams = pg.generate();
        //Pairing pairing = PairingFactory.getPairing(typeAParams);

        PairingFactory.getInstance().setUsePBCWhenPossible(true);
        pairing = PairingFactory.getPairing("assets/a128.properties");
        z = pairing.getZr();

        /*us = z.newRandomElement().getImmutable();
        ur = z.newRandomElement().getImmutable();
        ut = z.newRandomElement().getImmutable();*/

        us = z.newElement(451354322).getImmutable();  //source's main key
        ur = z.newElement(165486784).getImmutable();
        ut = z.newElement(165465798).getImmutable();
    }

    public void go(View v) {
        Spinner spinner = findViewById(R.id.spinner_identity);
        String identity = spinner.getSelectedItem().toString();
        getWorker(identity);
        worker.start();
    }

    public void initializeLogging() {
        LogWrapper logWrapper = new LogWrapper();
        Log.setLogNode(logWrapper);

        MessageOnlyLogFilter msgFilter = new MessageOnlyLogFilter();
        logWrapper.setNext(msgFilter);

        LogFragment logFragment = (LogFragment) getSupportFragmentManager()
                .findFragmentById(R.id.log_fragment);
        msgFilter.setNext(logFragment.getLogView());
    }

    public void getWorker(String identity) {
        if(worker != null) {
            worker.interrupt();
        }
        switch (identity) {
            case "Source" :
                worker = new SourceWorker();
                break;
            case "Relay":
                worker = new RelayWorker();
                break;
            case "Target":
                worker = new TargetWorker();
                break;
            case "Mitm" :
                relayMode = 1;
                worker = new RelayWorker();
                break;
            case "Capture":
                relayMode = 2;
                worker = new RelayWorker();
                break;
            case "ReplayS":
                sourceMode = 1;
                worker = new SourceWorker();
                break;
            case "ReplayR":
                relayMode = 3;
                worker = new RelayWorker();
                break;
            case "ReplayT":
                targetMode = 1;
                worker = new TargetWorker();
                break;
            case "Overhead":
                worker = new OverheadWorker();
                break;
            default:
                Log.d(TAG,"identity error");
        }
    }

    class SourceWorker extends Thread {
        static final String TAG = "SourceWorker";
        public void run() {
            int num;
            Element cvalue = z.newRandomElement().getImmutable(),
                    count, Tgn, n;
            Log.i(TAG, "You are UEs");

            byte[] t1 = new byte[16], t2 = new byte[16];
            byte[] m = "hello,world!".getBytes(); //the plain message
            byte[] buffer = new byte[2048];

            try {
                //1. session config
                socket = new Socket(AMF_IP, AMF_PORT);
                OutputStream output = socket.getOutputStream();
                InputStream input = socket.getInputStream();
                output.write("S".getBytes());

                if( sourceMode == 1 ){
                    IDs = IDr;
                    us = ur;
                    Kold = Kold2;
                }

                //long start = System.nanoTime();
                new SecureRandom().nextBytes(t1);
                output.write(Bytes.concat(IDs, IDt, t1));

                num = input.read(buffer);
                if (num != 48) {
                    Log.i(TAG, "error => sid n Tg(n)");
                    return;
                }
                byte[] sid = Arrays.copyOfRange(buffer, 0, 16);
                n = z.newElementFromBytes(Arrays.copyOfRange(buffer, 16, 32)).getImmutable();
                Tgn = z.newElementFromBytes(Arrays.copyOfRange(buffer, 32, 48)).getImmutable();
                Element Tus_n = T(us, n);

                output.write(Bytes.concat(sid, Tus_n.toBytes()));
                Log.i(TAG,  "step1 finished");

                //2. data transmit
                long start = System.nanoTime();
                new SecureRandom().nextBytes(t2);

                byte[] TID = byteArrayXor(IDs, IDt, 16);
                TID = byteArrayXor(TID, n.toBytes(), 16);
                byte[] CID = byteArrayXor(IDs, cvalue.toBytes(), 16);
                count = cvalue.add(z.newOneElement().getImmutable());

                byte[] Knew = byteArrayXor(Kold, t2, 16);
                Cipher cipher = Cipher.getInstance("AES/CFB8/NoPadding");
                cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(Knew, "AES"), ivspec);
                byte[] beta = cipher.doFinal(t2);
                Log.i(TAG,  String.format("Knew => %s", BaseEncoding.base16().lowerCase().encode(Knew)) );

                byte[] TS = ByteBuffer.allocate(4).putInt((int) (System.currentTimeMillis() / 1000)).array();

                cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(Kold, "AES"), ivspec);
                byte[] EM = cipher.doFinal(Bytes.concat(TS, t1, t2, m, beta ));

                Mac mac = Mac.getInstance("HmacMD5");
                mac.init(new SecretKeySpec(Kold, "RawBytes"));
                byte[] delta_m = mac.doFinal(Bytes.concat(sid, TID, EM));
                byte[] data = Bytes.concat(EM, delta_m);

                byte[] r1 = Tus_n.toBytes();
                Element Tus_tgn = T(us, Tgn);

                cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(Tus_tgn.toBytes(), "AES"), ivspec);
                byte[] e1 =  cipher.doFinal(t1);
                mac.init(new SecretKeySpec(Tus_tgn.toBytes(), "RawBytes"));
                byte[] delta_1 = mac.doFinal(Bytes.concat(r1, e1));
                byte[] R1 = Bytes.concat(r1, e1, delta_1);

                mac.init(new SecretKeySpec(n.toBytes(), "RawBytes"));
                byte[] delta_T = mac.doFinal((Bytes.concat(sid, TID, CID, count.toBytes(), data, R1)));
                byte[] msg = Bytes.concat(sid, TID, CID, count.toBytes(), data, R1, delta_T);

                if( sourceMode == 1 ){
                    FileInputStream fis = openFileInput(packetFile);
                    //byte[] packet =   new byte[(int) fis.getChannel().size()];
                    fis.read(msg);
                }

                Log.i(TAG,  "step2 finished ");
                long end = System.nanoTime();
                double t = (end-start)/1e6;
                Log.i(TAG,  String.format("send cipher data => %s", BaseEncoding.base16().lowerCase().encode(msg)) );
                Log.i(TAG, String.format("Source runtime => %sms", t));

                DatagramSocket udp_socket = new DatagramSocket();
                udp_socket.setBroadcast(true);
                for(int i = 0; i < 1000; i++)
                    udp_socket.send(new DatagramPacket(msg, msg.length, InetAddress.getByName("255.255.255.255"), 4001));


                //3. session confirm
                num = input.read(buffer);
                if (num != 32) {
                    Log.i(TAG,  "error => sid delta_c)");
                    return;
                }
                byte[] delta_ct = Arrays.copyOfRange(buffer, 16, 32);
                mac.init(new SecretKeySpec(Knew, "RawBytes"));
                byte[] delta_c = mac.doFinal(sid);

                if(!Arrays.equals(delta_c, delta_ct)) {
                    Log.i(TAG,  "not matched delta_c");
                    return;
                }
                Log.i(TAG,  "step3 finished");
                //long end = System.nanoTime();
                //double t = (end-start)/1e6;
                //Log.i(String.format("Total time for protocol => %sms", t));

            } catch (Exception e) {
                Log.i(TAG,  e.toString());
                return;
            }
        }
    }

    class RelayWorker extends Thread {
        static final String TAG = "RelayWorker";
        public void run() {
            int num;
            byte[] buffer = new byte[2048];
            Element Tgn, n;
            DatagramSocket serverSocket = null;
            Log.i(TAG,  "You are UER");

            try {
                //1. session config
                socket = new Socket(AMF_IP, AMF_PORT);
                OutputStream output = socket.getOutputStream();
                InputStream input = socket.getInputStream();
                output.write("R".getBytes());

                if( relayMode == 3 ){
                    ur = us;
                }

                num = input.read(buffer);
                if (num != 48) {
                    Log.i(TAG,  "error => sid n Tg(n)");
                    return;
                }
                byte[] sid = Arrays.copyOfRange(buffer, 0, 16);
                n = z.newElementFromBytes(Arrays.copyOfRange(buffer, 16, 32)).getImmutable();
                Tgn = z.newElementFromBytes(Arrays.copyOfRange(buffer, 32, 48)).getImmutable();

                Element Tur_n = T(ur, n);

                output.write(Bytes.concat(sid, Tur_n.toBytes()));
                Log.i(TAG,  "step1 finished");

                //2. data transmit
                serverSocket = new DatagramSocket(4001);
                serverSocket.setSoTimeout(4000);
                DatagramPacket receivePacket = new DatagramPacket(buffer,buffer.length);
                serverSocket.receive(receivePacket);
                int packetLength = receivePacket.getLength();
                Log.i(TAG,  String.format("Receive cipher data => %s", BaseEncoding.base16().lowerCase().encode(Arrays.copyOfRange(buffer, 0, packetLength))) );

                if( relayMode == 2 ){
                    try (FileOutputStream fos = openFileOutput(packetFile, Context.MODE_PRIVATE)) {
                        fos.write(Arrays.copyOfRange(buffer, 0, packetLength));
                    }
                }

                long start = System.nanoTime();
                byte[] sid_s = Arrays.copyOfRange(buffer, 0, 16);
                byte[] TID_s = Arrays.copyOfRange(buffer, 16, 32);
                byte[] CID_s = Arrays.copyOfRange(buffer, 32, 48);
                Element count = z.newElementFromBytes(Arrays.copyOfRange(buffer, 48, 64));
                count.add(z.newOneElement());

                byte[] data = Arrays.copyOfRange(buffer, 64, packetLength-64);
                byte[] R1_s = Arrays.copyOfRange(buffer, packetLength-64,
                        packetLength-16);
                byte[] delta_Ts = Arrays.copyOfRange(buffer, packetLength-16,
                        packetLength);

                if( relayMode == 1 ){ // relay modify attack
                    data[0] = (byte)(data[0] ^ 1);
                }

                if(!Arrays.equals(sid, sid_s)) {
                    Log.i(TAG,  "not matched sid");
                    return;
                }

                Mac mac = Mac.getInstance("HmacMD5");
                mac.init(new SecretKeySpec(n.toBytes(), "RawBytes"));
                byte[] delta_Ti = mac.doFinal(Arrays.copyOfRange(buffer, 0, packetLength - 16));
                if(!Arrays.equals(delta_Ti, delta_Ts)) {
                    Log.i(TAG,  "not matched delta t");
                    return;
                }


                byte[] r2 = Tur_n.toBytes();
                Cipher cipher = Cipher.getInstance("AES/CFB8/NoPadding");
                Element Tur_tgn = T(ur, Tgn);

                cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(Tur_tgn.toBytes(), "AES"), ivspec);
                byte[] e2 =  cipher.doFinal(Arrays.copyOfRange(R1_s, 16, 32));
                mac.init(new SecretKeySpec(Tur_tgn.toBytes(), "RawBytes"));
                byte[] delta_2 = mac.doFinal(Bytes.concat(r2, e2));
                byte[] R2 = Bytes.concat(r2, e2, delta_2);

                byte[] R = Bytes.concat(R1_s, R2);
                mac.init(new SecretKeySpec(n.toBytes(), "RawBytes"));
                byte[] delta_T = mac.doFinal((Bytes.concat(sid_s, TID_s, CID_s, count.toBytes(), data, R)));
                byte[] msg = Bytes.concat(sid_s, TID_s, CID_s, count.toBytes(), data, R, delta_T);

                Log.i(TAG,  "step2 finished");
                long end = System.nanoTime();
                double t = (end - start)/1e6;
                Log.i(TAG,  String.format("resend cipher data => %s", BaseEncoding.base16().lowerCase().encode(msg)) );
                Log.i(TAG, String.format("Relay runtime => %sms", t));

                DatagramSocket udp_socket = new DatagramSocket();
                udp_socket.setBroadcast(true);
                for(int i = 0; i < 1000; i++)
                    udp_socket.send(new DatagramPacket(msg, msg.length, InetAddress.getByName("255.255.255.255"), 4002));

            } catch (Exception e) {
                Log.i(TAG,  e.toString());
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
            Element Tgn, n;
            DatagramSocket serverSocket = null;
            Log.i(TAG,  "You are UEt");

            try {
                //1. session config
                socket = new Socket(AMF_IP, AMF_PORT);
                OutputStream output = socket.getOutputStream();
                InputStream input = socket.getInputStream();
                output.write("T".getBytes());

                if( targetMode == 1 ){
                    IDs = IDr;
                    Kold = Kold2;
                }

                num = input.read(buffer);
                if (num != 80) {
                    Log.i(TAG,  "error => sid n Tg(n) IDs t1");
                    return;
                }

                byte[] sid = Arrays.copyOfRange(buffer, 0, 16);
                n = z.newElementFromBytes(Arrays.copyOfRange(buffer, 16, 32)).getImmutable();
                Tgn = z.newElementFromBytes(Arrays.copyOfRange(buffer, 32, 48)).getImmutable();
                //byte[] IDs = Arrays.copyOfRange(buffer, 48, 64);
                byte[] t1 = Arrays.copyOfRange(buffer, 64, 80);
                Log.i(TAG,  "step1 finished");


                //2. data transmit
                serverSocket = new DatagramSocket(4002);
                serverSocket.setSoTimeout(4000);
                DatagramPacket receivePacket = new DatagramPacket(buffer,buffer.length);
                serverSocket.receive(receivePacket);
                int packetLength = receivePacket.getLength();
                Log.i(TAG,  String.format("Receive cipher data => %s", BaseEncoding.base16().lowerCase().encode(Arrays.copyOfRange(buffer, 0, packetLength))) );

                long start = System.nanoTime();
                byte[] sid_s = Arrays.copyOfRange(buffer, 0, 16);
                byte[] TID_s = Arrays.copyOfRange(buffer, 16, 32);
                byte[] CID_s = Arrays.copyOfRange(buffer, 32, 48);
                Element count = z.newElementFromBytes(Arrays.copyOfRange(buffer, 48, 64));

                byte[] data = Arrays.copyOfRange(buffer, 64, packetLength-112);
                byte[] R1_s = Arrays.copyOfRange(buffer, packetLength-112,
                        packetLength-16);
                byte[] delta_Ts = Arrays.copyOfRange(buffer, packetLength-16,
                        packetLength);

                if(!Arrays.equals(sid, sid_s)) {
                    Log.i(TAG,  "not matched sid");
                    return;
                }

                Mac mac = Mac.getInstance("HmacMD5");
                mac.init(new SecretKeySpec(n.toBytes(), "RawBytes"));
                byte[] delta_Tt = mac.doFinal(Arrays.copyOfRange(buffer, 0, packetLength - 16));
                if(!Arrays.equals(delta_Tt, delta_Ts)) {
                    Log.i(TAG,  "not matched delta t");
                    return;
                }

                byte[] IDs_t = byteArrayXor(TID_s, IDt, 16);
                IDs_t = byteArrayXor(IDs_t, n.toBytes(), 16);
                if(!Arrays.equals(IDs_t, IDs)) {
                    Log.i(TAG,  "not matched IDs");
                    return;
                }

                Element cvalue = z.newElementFromBytes(byteArrayXor(CID_s, IDs, 16));
                if(! count.sub(cvalue).isEqual(z.newElement(R1_s.length / 48))) {
                    Log.i(TAG,  "not matched track length");
                    return;
                }

                byte[] EM = Arrays.copyOfRange(data, 0, data.length-16);
                mac.init(new SecretKeySpec(Kold, "RawBytes"));
                byte[] delta_mt = mac.doFinal(Bytes.concat(sid_s, TID_s, EM));
                if(!Arrays.equals(delta_mt, Arrays.copyOfRange(data,  data.length-16, data.length))) {
                    Log.i(TAG,  "not matched delta_m");
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
                    Log.i(TAG,  "not matched t1");
                    return;
                }

                byte[] Knew = byteArrayXor(Kold, t2_t, 16);
                cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(Knew, "AES"), ivspec);
                byte[] beta_tt =  cipher.doFinal(t2_t);
                if(!Arrays.equals(beta_tt, beta_t)) {
                    Log.i(TAG,  "not matched beta");
                    return;
                }
                Log.i(TAG,  String.format("Knew => %s", BaseEncoding.base16().lowerCase().encode(Knew)) );
                Log.i(TAG,  "step2 finished");

                //3. session confirm
                mac.init(new SecretKeySpec(Knew, "RawBytes"));
                byte[] delta_c = mac.doFinal(sid);
                output.write(Bytes.concat(sid, delta_c, R1_s));
                Log.i(TAG,  "step3 finished");
                long end = System.nanoTime();
                double t = (end - start)/1e6;
                Log.i(TAG, String.format("Target runtime => %sms", t));

            } catch (Exception e) {
                Log.i(TAG,  e.toString());
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
            Log.i(TAG, String.format("Average pairing time => %sms", t));

            x = z.newRandomElement().getImmutable();
            y = z.newRandomElement().getImmutable();
            start = System.nanoTime();
            for (i = 0; i < times; i++) {
                x.mulZn(y);
            }
            end = System.nanoTime();
            t = (end - start) / 1e6 / times;
            Log.i(TAG, String.format("Average mul time => %sms", t));

            start = System.nanoTime();
            for (i = 0; i < times; i++) {
                x.powZn(y);
            }
            end = System.nanoTime();
            t = (end - start) / 1e6 / times;
            Log.i(TAG, String.format("Average exp time => %sms", t));

            start = System.nanoTime();
            for (i = 0; i < times; i++) {
                z.newElementFromHash(plain, 0, 16);
            }
            end = System.nanoTime();
            t = (end - start) / 1e6 / times;
            Log.i(TAG, String.format("Average hash time => %sms", t));

            try {
                Mac mac = Mac.getInstance("HmacMD5");
                mac.init(new SecretKeySpec(IK, "RawBytes"));
                start = System.nanoTime();
                for (i = 0; i < times; i++) {
                    mac.doFinal(plain);
                }
                end = System.nanoTime();
                t = (end - start) / 1e6 / times;
                Log.i(TAG, String.format("Average hmac time => %sms", t));


                Cipher cipher = Cipher.getInstance("AES/CFB8/NoPadding");
                cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(CK, "AES"), ivspec);
                start = System.nanoTime();
                for (i = 0; i < times; i++) {
                    cipher.doFinal(plain);
                }
                end = System.nanoTime();
                t = (end - start) / 1e6 / times;
                Log.i(TAG, String.format("Average encrypt time => %sms", t));
            } catch (Exception e) {
                Log.i(TAG, e.toString());
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

    private static Element[][] matmul(Element[][] m1, Element[][] m2) {
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

