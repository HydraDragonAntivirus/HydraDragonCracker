using System;
using System.Windows.Forms;

class TestLoader
{
    static void Main()
    {
        try
        {
            Console.WriteLine("Testing System.Windows.Forms loading...");
            Console.WriteLine("Assembly location: " + typeof(Application).Assembly.Location);
            
            Application.EnableVisualStyles();
            Console.WriteLine("SUCCESS: Application.EnableVisualStyles() called");
            
            Console.ReadLine();
        }
        catch (Exception ex)
        {
            Console.WriteLine("ERROR: " + ex.ToString());
            Console.ReadLine();
        }
    }
}

