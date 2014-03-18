------------------------------------------------------------------------------
--                              Ada Web Server                              --
--                                                                          --
--                     Copyright (C) 2004-2014, AdaCore                     --
--                                                                          --
--  This is free software;  you can redistribute it  and/or modify it       --
--  under terms of the  GNU General Public License as published  by the     --
--  Free Software  Foundation;  either version 3,  or (at your option) any  --
--  later version.  This software is distributed in the hope  that it will  --
--  be useful, but WITHOUT ANY WARRANTY;  without even the implied warranty --
--  of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU     --
--  General Public License for  more details.                               --
--                                                                          --
--  You should have  received  a copy of the GNU General  Public  License   --
--  distributed  with  this  software;   see  file COPYING3.  If not, go    --
--  to http://www.gnu.org/licenses for a complete copy of the license.      --
------------------------------------------------------------------------------

--  Test file as attachment

with Ada.Exceptions;
with Ada.Text_IO;
with Ada.Strings.Unbounded;

with AWS.Client;
with AWS.Config.Set;
with AWS.Messages;
with AWS.Net.SSL;
with AWS.MIME;
with AWS.Response;
with AWS.Resources.Streams.Disk;
with AWS.Server.Status;
with AWS.Status;
with AWS.Utils;

package body S_AFile_Pack is

   use Ada;
   use AWS;

   package ASU renames Ada.Strings.Unbounded;

   WS   : Server.HTTP;
   CNF  : Config.Object;
   FN   : constant String := "test.out";
   Size : constant Response.Content_Length_Type
    := Response.Content_Length_Type (Resources.File_Size (FN));
   Cli  : AWS.Client.HTTP_Connection;

   Socket  : Net.Socket_Access;
   Session : ASU.Unbounded_String;
   --  Check for the change session and socket

   --------
   -- CB --
   --------

   function CB (Request : Status.Data) return Response.Data is
      Strm : Resources.Streams.Stream_Access;
      URI  : constant String := Status.URI (Request);
      Sock : Net.Socket_Access := Status.Socket (Request);

      procedure Same_Session (Condition : Boolean);

      function Same_Socket return Boolean;

      ------------------
      -- Same_Session --
      ------------------

      procedure Same_Session (Condition : Boolean) is
         Sessn  : constant String :=
                    Net.SSL.Session_Id_Image (Net.SSL.Socket_Type (Sock.all));
         Result : constant Boolean := ASU.To_String (Session) = Sessn;
      begin
         if (ASU.To_String (Session) = Sessn) /= Condition then
            if Condition then
               Text_IO.Put_Line
                 ("Unexpected session differ " & ASU.To_String (Session)
                  & ' ' & Sessn);
            else
               Text_IO.Put_Line ("Unexpected same session");
            end if;
         end if;

         Session := ASU.To_Unbounded_String (Sessn);
      end Same_Session;

      -----------------
      -- Same_Socket --
      -----------------

      function Same_Socket return Boolean is
         use type Net.Socket_Access;
         Result : constant Boolean :=
                    Sock = Socket
                      and then Sock.Get_FD = Socket.Get_FD
                      and then Sock.Get_Port = Socket.Get_Port;
      begin
         Socket := Sock;

         return Result;
      end Same_Socket;

   begin
      if URI = "/first" then
         Socket := Sock;
         Session :=
           ASU.To_Unbounded_String
             (Net.SSL.Session_Id_Image (Net.SSL.Socket_Type (Sock.all)));

         return Response.File
           (MIME.Application_Octet_Stream, FN,
            Disposition => Response.Inline);

      elsif URI = "/second" then
         if not Same_Socket then
            Text_IO.Put_Line ("Unexpected change socket");
         end if;

         Same_Session (True);

         return Response.File
           (MIME.Application_Octet_Stream, FN,
            Disposition => Response.Attachment);

      elsif URI = "/third" then
         if Same_Socket then
            Text_IO.Put_Line ("Unexpected same socket");
         end if;

         Same_Session (False);

         return Response.File
           (MIME.Application_Octet_Stream, FN,
            User_Filename => "you_got_this.o",
            Disposition => Response.Inline);

      elsif URI = "/fourth" then
         if Same_Socket then
            Text_IO.Put_Line ("Unexpected same socket");
         end if;

         Same_Session (True);

         return Response.File
           (MIME.Application_Octet_Stream, FN,
            Disposition   => Response.Attachment,
            User_Filename => "you_got_this.o");

      elsif URI = "/fifth" then
         if Same_Socket then
            Text_IO.Put_Line ("Unexpected same socket");
         end if;

         Same_Session (False);

         Strm :=  new Resources.Streams.Disk.Stream_Type;
         Resources.Streams.Disk.Open
           (Resources.Streams.Disk.Stream_Type (Strm.all), FN);
         return Response.Stream
           (MIME.Application_Octet_Stream, Strm,
            Disposition => Response.Inline);

      elsif URI = "/sixth" then
         if Same_Socket then
            Text_IO.Put_Line ("Unexpected same socket");
         end if;

         Same_Session (True);

         Strm :=  new Resources.Streams.Disk.Stream_Type;
         Resources.Streams.Disk.Open
           (Resources.Streams.Disk.Stream_Type (Strm.all), FN);
         return Response.Stream
           (MIME.Application_Octet_Stream, Strm,
            Disposition => Response.Attachment);

      elsif URI = "/seventh" then
         if Same_Socket then
            Text_IO.Put_Line ("Unexpected same socket");
         end if;

         Same_Session (True);

         Strm :=  new Resources.Streams.Disk.Stream_Type;
         Resources.Streams.Disk.Open
           (Resources.Streams.Disk.Stream_Type (Strm.all), FN);
         return Response.Stream
           (MIME.Application_Octet_Stream, Strm,
            User_Filename => "a_stream.o", Disposition => Response.Inline);

      elsif URI = "/eighth" then
         if Same_Socket then
            Text_IO.Put_Line ("Unexpected same socket");
         end if;

         Same_Session (True);

         Strm :=  new Resources.Streams.Disk.Stream_Type;
         Resources.Streams.Disk.Open
           (Resources.Streams.Disk.Stream_Type (Strm.all), FN);
         return Response.Stream
           (MIME.Application_Octet_Stream, Strm,
            Disposition   => Response.Attachment,
            User_Filename => "a_stream.o");

      elsif URI = "/nineth" then
         if Same_Socket then
            Text_IO.Put_Line ("Unexpected same socket");
         end if;

         Same_Session (True);

         return Response.File (MIME.Application_Octet_Stream, FN);

      elsif URI = "/tenth" then
         if Same_Socket then
            Text_IO.Put_Line ("Unexpected same socket");
         end if;

         Same_Session (True);

         Strm :=  new Resources.Streams.Disk.Stream_Type;
         Resources.Streams.Disk.Open
           (Resources.Streams.Disk.Stream_Type (Strm.all), FN);
         return Response.Stream (MIME.Application_Octet_Stream, Strm);

      else
         return Response.Build
                  (MIME.Text_HTML, "URI """ & URI & """ not supported");
      end if;

   exception
      when E : others =>
         Text_IO.Put_Line
           ("CB error: " & Exceptions.Exception_Information (E));
         return Response.Build
           (MIME.Text_Plain,
            Exceptions.Exception_Message (E),
            Messages.S500);
   end CB;

   ---------
   -- Run --
   ---------

   procedure Run (Protocol : String) is

      Port : Positive;

      -------------
      -- Call_It --
      -------------

      procedure Call_It (Res : String) is
         use type Response.Content_Length_Type;
         R : Response.Data;
      begin
         Client.Get (Cli, R, '/' & Res);

         declare
            Sessn : constant String := AWS.Client.SSL_Session_Id (Cli);
         begin
            if ASU.To_String (Session) /= Sessn then
               Text_IO.Put_Line
                 ("Server and client sessions differ "
                  & ASU.To_String (Session) & ' ' & Sessn);
            end if;
         end;

         Text_IO.Put (Res);
         Text_IO.Set_Col (9);
         Text_IO.Put_Line
           ("= " & Response.Header (R, Messages.Content_Disposition_Token, 1));

         declare
            S : constant Response.Content_Length_Type
              := Response.Content_Length (R);
         begin
            if S = Response.Undefined_Length then
               Text_IO.Put_Line ("Error: " & Res & " undefined size.");
            elsif Size /= S then
               Text_IO.Put_Line ("Error : " & Res & " wrong size.");
            end if;
         end;
      end Call_It;

   begin
      Config.Set.Server_Name    (CNF, "afile " & Protocol);
      Config.Set.Server_Host    (CNF, "localhost");
      Config.Set.Server_Port    (CNF, 0);
      Config.Set.Security       (CNF, Protocol = "https");
      Config.Set.Max_Connection (CNF, 5);

      Server.Start (WS, CB'Access, CNF);

      Port := Server.Status.Port (WS);

      Text_IO.Put_Line ("started"); Ada.Text_IO.Flush;

      delay 0.25;

      AWS.Client.Create (Cli, Server.Status.Local_URL (WS));

      Call_It ("first");
      AWS.Client.Set_Persistent (Cli, False);
      Call_It ("second");
      AWS.Client.Clear_SSL_Session (Cli);
      Call_It ("third");
      Call_It ("fourth");
      AWS.Client.Clear_SSL_Session (Cli);
      Call_It ("fifth");
      Call_It ("sixth");
      Call_It ("seventh");
      Call_It ("eighth");
      Call_It ("nineth");
      Call_It ("tenth");

      Server.Shutdown (WS);
      Text_IO.Put_Line ("shutdown");

   exception
      when E : others =>
         Text_IO.Put_Line
           ("Main error: " & Exceptions.Exception_Information (E));
   end Run;

end S_AFile_Pack;
