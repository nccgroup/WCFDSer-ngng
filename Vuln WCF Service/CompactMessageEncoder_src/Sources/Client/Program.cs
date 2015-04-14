using System;
using System.Collections.Generic;
using System.Text;
using System.IO;
using System.Data.SqlClient;
using System.Data;

namespace Client
{
    class Program
    {
        static void Main(string[] args)
        {
            while (true)
            {
                MyServiceProxy myService = new MyServiceProxy();

                Console.WriteLine("\r\nEnter a name");
                string data = myService.GetLargeData(Console.ReadLine());

                Console.WriteLine(data);
            }    
        }
    }
}
