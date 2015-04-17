import java.io.InputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;

public class nol
{
    public static void main(String[] argv)
    {
        InputStream f;
        int chr;
        int lines = 0;

        try
        {
            if(argv.length > 1)
            {
                f = new FileInputStream(argv[1]);
            }
            else
            {
                f = System.in;
            }

            do
            {
                chr = f.read();
                if(chr == '\n')
                {
                    lines++;
                }
            } while(chr != -1);

            f.close();

            System.out.printf("Number of lines: %d\n", lines);
            System.exit(0);
        }
        catch (FileNotFoundException ex)
        {
            System.out.printf("Error: %s - file not found.\n", argv[1]);
            System.exit(1);
        }
        catch (IOException ex)
        {
            System.exit(1);
        }
    }
}

