using System;
using System.Collections.Generic;
using System.Text;
using System.ServiceModel;
using System.IO;

namespace Client
{
    [ServiceContract(ConfigurationName = "Client.IMyService")]
    public interface IMyService
    {
        [OperationContract]
        string GetLargeData(string input);
    }

    public class MyServiceProxy : ClientBase<IMyService>, IMyService
    {
        public MyServiceProxy()
        {
        }

        public string GetLargeData(string input)
        {
            return base.Channel.GetLargeData(input);
        }
    }
}
