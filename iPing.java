import com.ibm.as400.access.AS400JPing;
import com.ibm.as400.access.AS400;


class iPing
{
  public static void main( String[] args )
  {
    AS400JPing pingObj = new AS400JPing(args[0],99,false); //all services
    if ( pingObj.ping() )
    {
      System.out.println("SUCCESS");
    }
    else
    {
      System.out.println("FAILED");
    }
  } //end main()
} //end iPing class