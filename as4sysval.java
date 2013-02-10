//Java program to get System Values
//import com.ibm.as400.access.*;
import com.ibm.as400.access.AS400;
import com.ibm.as400.access.SystemValueGroup;
import com.ibm.as400.access.SystemValue;
import com.ibm.as400.access.SystemValueList;
import java.io.BufferedWriter;
import java.io.FileWriter;
import java.util.Vector;

class as4sysval
{
  public static void main (String[] args)
  {
    AS400 sys = null;             //AS400 system
    String system = args[0];      //iSeries ip address
    Vector systemValues = null;   //vector to hold system values
    String newline = System.getProperty("line.separator");
    String outFileName = args[3] + "\\as4.system.values.txt";

    try
    {
     BufferedWriter outFile = new BufferedWriter(new FileWriter(outFileName));
     String outLine = "";

     //connect to system
     sys  = new AS400(system,args[1],args[2]);

     //retrieve the security related system valuse and any other that we specify
 	   String svName = "Security Related Values";
     String svDescription = "The relevant security related system values.";

     //get all security related system values
     SystemValueGroup svGroup = new SystemValueGroup(sys,svName,svDescription,SystemValueList.GROUP_SEC);

     //add/remove some
     svGroup.add("QAUTOVRT");
     svGroup.add("QATNPGM");
     svGroup.remove("QDSPSGNINF");
     svGroup.remove("QSCANFS");
     svGroup.remove("QSCANFSCTL");

     //retrieve system values vector
     systemValues = svGroup.getSystemValues();

     //process system values, do analysis, and write out file
     for (int i = 0; i < systemValues.size(); i++)
     {
      //retrieve data
      SystemValue sv = (SystemValue)systemValues.elementAt(i);

      //system val's name
      String name = (String) sv.getName();

      //setting
      Object val = sv.getValue();

      //description
      String desc = sv.getDescription();

      //need to determine it's class to make sure the casting goes smoothly
      //have to cast to either a String or array of Strings
      String cls = val.getClass().toString();

      if (cls.equals("class [Ljava.lang.String;"))
      {
       //array of strings
       String[] arr = (String[])val;
       String outValue = "[";
       for (int j = 0; j < arr.length; j++)
       {
        outValue = outValue + arr[j] + " ";
       }
       outValue = outValue + "]";

       //write out to file
       outLine = name + "|" + outValue + "|" + desc + newline;
      }else
      {
       //just a string or integer, so get string representation and go from there
       String outValue = sv.getValue().toString();
       outLine = name + "|" + outValue + "|" + desc + newline;
      }

      //write output
      outFile.write(outLine);

     }

   outFile.flush();
   outFile.close();
   sys.disconnectAllServices();

  }catch (Exception e)
  {
   System.out.println("Error occurred during processing.");
   e.printStackTrace();
   System.out.println("");
   System.out.println("***If processing at SMWE, make sure Secure Client is not running***");
   System.exit(1);
  }

  System.exit(0);

 } //end main() method
} //end AS4SystemValues class
