--                              ADA ON RAILS                                --
--                                                                          --
--                     Copyright (C) 2010-2021, AdaLabs Ltd                 --
--                                                                          --
--  This library is free software;  you can redistribute it and/or modify   --
--  it under terms of the  GNU General Public License  as published by the  --
--  Free Software  Foundation;  either version 3,  or (at your  option) any --
--  later version. This library is distributed in the hope that it will be  --
--  useful, but WITHOUT ANY WARRANTY;  without even the implied warranty of --
--  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.                    --
--                                                                          --
--  As a special exception under Section 7 of GPL version 3, you are        --
--  granted additional permissions described in the GCC Runtime Library     --
--  Exception, version 3.1, as published by the Free Software Foundation.   --
--                                                                          --
--  You should have received a copy of the GNU General Public License and   --
--  a copy of the GCC Runtime Library Exception along with this program;    --
--  see the files COPYING3 and COPYING.RUNTIME respectively.  If not, see   --
--  <http://www.gnu.org/licenses/>.                                         --
--                                                                          --
--  As a special exception, if other files instantiate generics from this   --
--  unit, or you link this unit with other files to produce an executable,  --
--  this  unit  does not  by itself cause  the resulting executable to be   --
--  covered by the GNU General Public License. This exception does not      --
--  however invalidate any other reasons why the executable file  might be  --
--  covered by the  GNU Public License.                                     --
------------------------------------------------------------------------------
with Ada.Strings.Unbounded;
use Ada.Strings.Unbounded;

with AWS.URL,
     AWS.Utils,
     AWS.Messages,
     AWS.Response.Set;

package body AWS.Cookie.Extras is

   Version_Token   : constant String := "Version=1";

   Same_Site_Token : constant String := "SameSite";
   None_Token      : constant String := "None";
   Lax_Token       : constant String := "Lax";
   Strict_Token    : constant String := "Strict";

   ---------
   -- Expire --
   --------

   procedure Expire (Content   : in out Response.Data;
                     Key       : String;
                     Same_Site : Same_Site_Kinds;
                     Path      : String := "/")
   is
   begin
      AWS.Cookie.Extras.Set (Content   => Content,
                             Key       => Key,
                             Value     => "",
                             Same_Site => Same_Site,
                             Max_Age   => 0.0,
                             Path      => Path);
   end Expire;

   ---------
   -- Set --
   ---------

   procedure Set (Content   : in out Response.Data;
                  Key       : String;
                  Value     : String;
                  Same_Site : Same_Site_Kinds;
                  Comment   : String := "";
                  Domain    : String := "";
                  Max_Age   : Duration := Default.Ten_Years;
                  Path      : String := "/";
                  Secure    : Boolean := False;
                  HTTP_Only : Boolean := False)
   is

      procedure Add (Str : String);
      --  Add value with separator if needed into the cookie value

      Cookie_Content : Unbounded_String;

      ---------
      -- Add --
      ---------

      procedure Add (Str : String) is
      begin
         if Cookie_Content /= Null_Unbounded_String then
            Append (Cookie_Content, "; ");
         end if;

         Append (Cookie_Content, Str);
      end Add;

      Value_Part : constant String := Key & "=" & AWS.URL.Encode (Value);
      Path_Part  : constant String := AWS.Messages.Path_Token & "=" & Path;

   begin
      if Response.Mode (Content) = Response.No_Data then
         raise Response_Data_Not_Initialized;
      end if;

      Add (Value_Part);
      Add (Path_Part);

      if Max_Age /= No_Max_Age then
         Add (Messages.Max_Age_Token & "=" & 
              AWS.Utils.Image (Natural (Max_Age)));
      end if;

      if Comment /= "" then
         Add (Messages.Comment_Token & "=" & Comment);
      end if;

      if Domain /= "" then
         Add (Messages.Domain_Token & "=" & Domain);
      end if;

      case Same_Site is
         when None =>
            Add (Same_Site_Token & "=" & None_Token);
            Add (Messages.Secure_Token);
         when Lax =>
            Add (Same_Site_Token & "=" & Lax_Token);
            if Secure then
               Add (Messages.Secure_Token);
            end if;
         when Strict =>
            Add (Same_Site_Token & "=" & Strict_Token);
            if Secure then
               Add (Messages.Secure_Token);
            end if;
      end case;

      if HTTP_Only then
         Add (Messages.HTTP_Only_Token);
      end if;

      Add (Version_Token);

      AWS.Response.Set.Add_Header (Content,
                                   Name  => Messages.Set_Cookie_Token,
                                   Value => To_String (Cookie_Content));
   end Set;
end AWS.Cookie.Extras;
