using System;
using System.Collections.Generic;
using System.Text;
using System.ServiceModel;
using System.IO;
using System.Data.SqlClient;
using System.Data;

namespace Server
{

    [ServiceContract]
    public interface IMyService
    {
        [OperationContract]
        string GetLargeData(string input);
    }

    [ServiceBehavior(AddressFilterMode = AddressFilterMode.Any)]
    public class MyService : IMyService
    {
        #region IMyService Members

        public string GetLargeData(string input)
        {
            string str = "Data Source=.\\SQLEXPRESS;Initial Catalog=master;Integrated Security=True";
            SqlConnection con = new SqlConnection(str);
            SqlCommand cmd = new SqlCommand();
            SqlDataReader reader;

            cmd.CommandText = "SELECT LastName FROM [AdventureWorks2012].[Person].[Person] where FirstName = '" + input + "'";
            cmd.CommandType = CommandType.Text;
            cmd.Connection = con;

            con.Open();
            StringBuilder sb = new StringBuilder();

            try
            {
                reader = cmd.ExecuteReader();
      
                if (reader.HasRows)
                {
                    while (reader.Read())
                    {
                        sb.Append(reader.GetString(0) + "---");
                    }
                }
            }
            catch(Exception ex)
            {
                sb.Append(ex.ToString());
            }

            con.Close();
            con.Dispose();
     
            return sb.ToString().Length > 65534 ? sb.ToString().Substring(0, 64434) : sb.ToString();
        }
        #endregion

        private string GenerateLargeString()
        {
            StringBuilder sb = new StringBuilder();

            // Dumb function to generate large string
            for (int i = 0; i < 1000; ++i)
            {
                sb.Append("abcdefghijklmnopqrstuvwxyz1234567890");
            }

            return sb.ToString();
        }
    }
}
