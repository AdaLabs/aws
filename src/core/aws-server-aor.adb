pragma Ada_2012;

with AWS.Log,
     AWS.Messages;


package body AWS.Server.AOR is

   procedure Reload_SSL_Certificate (Web_Server : in out HTTP)
   is
      use type AWS.Net.SSL.Config;
      -------------------
      -- Security_Mode --
      -------------------

      function Security_Mode return Net.SSL.Method;
      function Security_Mode return Net.SSL.Method is
      begin
         return Net.SSL.Method'Value
           (CNF.Security_Mode (Web_Server.Properties));
      exception
         when Constraint_Error =>
            return Net.SSL.Method'Value (Default.Security_Mode);
      end Security_Mode;
   begin
      if CNF.Security (Web_Server.Properties) then
         if Web_Server.SSL_Config /= Net.SSL.Null_Config then
            AWS.Log.Write
              (Web_Server.Log,
               "Reloading SSL certificate");
            Net.SSL.Release (Web_Server.SSL_Config);
            Net.SSL.Initialize
              (Web_Server.SSL_Config,
               Security_Mode,
               Server_Certificate   =>
                 CNF.Server_Certificate (Web_Server.Properties),
               Server_Key           =>
                 CNF.Server_Key (Web_Server.Properties),
               Priorities           =>
                 CNF.Cipher_Priorities (Web_Server.Properties),
               Ticket_Support       =>
                 CNF.TLS_Ticket_Support (Web_Server.Properties),
               Exchange_Certificate =>
                 CNF.Exchange_Certificate (Web_Server.Properties),
               Check_Certificate    =>
                 CNF.Check_Certificate (Web_Server.Properties),
               Trusted_CA_Filename  =>
                 CNF.Trusted_CA (Web_Server.Properties),
               CRL_Filename         =>
                 CNF.CRL_File (Web_Server.Properties),
               Session_Cache_Size   =>
                 CNF.SSL_Session_Cache_Size (Web_Server.Properties));
         end if;

         if CNF.HTTP2_Activated (Web_Server.Properties) then
            Net.SSL.ALPN_Include (Web_Server.SSL_Config, Messages.H2_Token);
         end if;
      end if;

   end Reload_SSL_Certificate;

end AWS.Server.AOR;
