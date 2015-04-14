using System;
using System.Collections.Generic;
using System.Text;
using System.ServiceModel;

namespace Server
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Starting service...");
            StartService();

            Console.WriteLine("Press any key to stop service");
            Console.ReadKey(true);

            Console.WriteLine("Stoppping service...");
            StopService();
        }

        private static ServiceHost myServiceHost = null;

        private static void StartService()
        {
            Uri baseAddress = new Uri("net.tcp://localhost:1234");

            myServiceHost = new ServiceHost(typeof(Server.MyService), baseAddress);

            myServiceHost.Open();
        }

        private static void StopService()
        {
            //Call StopService from your shutdown logic (i.e. dispose method)
            if (myServiceHost.State != CommunicationState.Closed)
            {
                myServiceHost.Close();
            }
        }
    }
}
