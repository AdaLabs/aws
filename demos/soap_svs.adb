------------------------------------------------------------------------------
--                              Ada Web Server                              --
--                                                                          --
--                         Copyright (C) 2000-2001                          --
--                                ACT-Europe                                --
--                                                                          --
--  Authors: Dmitriy Anisimkov - Pascal Obry                                --
--                                                                          --
--  This library is free software; you can redistribute it and/or modify    --
--  it under the terms of the GNU General Public License as published by    --
--  the Free Software Foundation; either version 2 of the License, or (at   --
--  your option) any later version.                                         --
--                                                                          --
--  This library is distributed in the hope that it will be useful, but     --
--  WITHOUT ANY WARRANTY; without even the implied warranty of              --
--  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU       --
--  General Public License for more details.                                --
--                                                                          --
--  You should have received a copy of the GNU General Public License       --
--  along with this library; if not, write to the Free Software Foundation, --
--  Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.          --
--                                                                          --
--  As a special exception, if other files instantiate generics from this   --
--  unit, or you link this unit with other files to produce an executable,  --
--  this  unit  does not  by itself cause  the resulting executable to be   --
--  covered by the GNU General Public License. This exception does not      --
--  however invalidate any other reasons why the executable file  might be  --
--  covered by the  GNU Public License.                                     --
------------------------------------------------------------------------------

--  $Id$

--  A SOAP server that implements all Web Services on the following validation
--  suite: http://soap.weblogs.com/validator1. This implementation has passed
--  all the tests on:
--
--     Never at this point.

with Ada.Text_IO;
with Ada.Command_Line;

with AWS.Response;
with AWS.Server;
with AWS.Status;

with SOAP.Message.XML;
with SOAP.Message.Payload;
with SOAP.Message.Response.Error;
with SOAP.Parameters;
with SOAP.Types;

procedure SOAP_SVS is

   use Ada;

   Quiet : Boolean := True;
   --  Set to False with -t option (trace mode).

   WS    : AWS.Server.HTTP;

   function SOAP_CB (Request : in AWS.Status.Data) return AWS.Response.Data;
   --  Callback used when SOAPAction is /validator1

   ------------------------------
   -- SOAP Validation Callback --
   ------------------------------

   function SOAP_Count_The_Entities
     (PL : in SOAP.Message.Payload.Object)
     return AWS.Response.Data;

   function SOAP_Easy_Struct_Test
     (PL : in SOAP.Message.Payload.Object)
     return AWS.Response.Data;

   function SOAP_Echo_Struct_Test
     (PL : in SOAP.Message.Payload.Object)
     return AWS.Response.Data;

   function SOAP_Many_Types_Test
     (PL : in SOAP.Message.Payload.Object)
     return AWS.Response.Data;

   function SOAP_Moderate_Size_Array_Check
     (PL : in SOAP.Message.Payload.Object)
     return AWS.Response.Data;

   function SOAP_Nested_Struct_Test
     (PL : in SOAP.Message.Payload.Object)
     return AWS.Response.Data;

   function SOAP_Simple_Struct_Return_Test
     (PL : in SOAP.Message.Payload.Object)
     return AWS.Response.Data;

   function SOAP_Which_Toolkit
     (PL : in SOAP.Message.Payload.Object)
     return AWS.Response.Data;

   --------
   -- CB --
   --------

   function CB (Request : in AWS.Status.Data) return AWS.Response.Data is
      SOAPAction : constant String := AWS.Status.SOAPAction (Request);
   begin
      if SOAPAction = "/validator1" then
         return SOAP_CB (Request);

      else
         return AWS.Response.Build
           ("text/html",
            "<p>This is not a SOAP action !");
      end if;
   end CB;

   -------------
   -- SOAP_CB --
   -------------

   function SOAP_CB (Request : in AWS.Status.Data) return AWS.Response.Data is
      use SOAP.Types;
      use SOAP.Parameters;

      XML_Payload : constant String
        := AWS.Status.Payload (Request);

      PL : constant SOAP.Message.Payload.Object
        := SOAP.Message.XML.Load_Payload (XML_Payload);

      Proc_Name : constant String :=
        SOAP.Message.Payload.Procedure_Name (PL);

   begin
      --  Print SOAP request for the demo

      if not Quiet then
         Text_IO.Put_Line ("SOAP Request");

         Text_IO.Put_Line ("Payload : " & AWS.Status.Payload (Request));

         Text_IO.Put_Line ("   Procedure : " & Proc_Name);
      end if;

      --  Test the procedure to call

      if Proc_Name = "countTheEntities" then
         return SOAP_Count_The_Entities (PL);

      elsif Proc_Name = "easyStructTest" then
         return SOAP_Easy_Struct_Test (PL);

      elsif Proc_Name = "echoStructTest" then
         return SOAP_Echo_Struct_Test (PL);

      elsif Proc_Name = "manyTypesTest" then
         return SOAP_Many_Types_Test (PL);

      elsif Proc_Name = "moderateSizeArrayCheck" then
         return SOAP_Moderate_Size_Array_Check (PL);

      elsif Proc_Name = "nestedStructTest" then
         return SOAP_Nested_Struct_Test (PL);

      elsif Proc_Name = "simpleStructReturnTest" then
         return SOAP_Simple_Struct_Return_Test (PL);

      elsif Proc_Name = "whichToolkit" then
         return SOAP_Which_Toolkit (PL);

      else
         return AWS.Response.Build
           ("text/html",
            "<p>Not yet implemented !");
      end if;

   exception
      when SOAP.Types.Data_Error =>
         return SOAP.Message.Response.Build
           (SOAP.Message.Response.Error.Build
            (SOAP.Message.Response.Error.Client, "Parameter error"));
   end SOAP_CB;

   -----------------------------
   -- SOAP_Count_The_Entities --
   -----------------------------

   function SOAP_Count_The_Entities
     (PL : in SOAP.Message.Payload.Object)
     return AWS.Response.Data
   is
      use SOAP.Types;
      use SOAP.Parameters;

      P  : constant SOAP.Parameters.List := SOAP.Message.Parameters (PL);

      R  : SOAP.Message.Response.Object;
      RP : SOAP.Parameters.List;

   begin
      --  Print SOAP request for the demo

      if not Quiet then
         Text_IO.Put_Line ("SOAP Request countTheEntities");

         Text_IO.Put_Line ("  "
                           & Natural'Image (SOAP.Parameters.Argument_Count (P))
                           & " parameter(s)");

         Text_IO.Put_Line
           ("   s = " & SOAP.Types.Image (SOAP.Parameters.Argument (P, "s")));

         Text_IO.New_Line;
      end if;

      --  Real job start here

      R := SOAP.Message.Response.From (PL);

      declare
         S : constant String := SOAP.Parameters.Get (P, "s");

         ctLeftAngleBrackets  : Natural := 0;
         ctRightAngleBrackets : Natural := 0;
         ctAmpersands         : Natural := 0;
         ctApostrophes        : Natural := 0;
         ctQuotes             : Natural := 0;

         OS : Object_Set (1 .. 5);
      begin
         for K in S'Range loop
            case S (K) is
               when '<' => ctLeftAngleBrackets  := ctLeftAngleBrackets + 1;
               when '>' => ctRightAngleBrackets := ctRightAngleBrackets + 1;
               when '&' => ctAmpersands         := ctAmpersands + 1;
               when ''' => ctApostrophes        := ctApostrophes + 1;
               when '"' => ctQuotes             := ctQuotes + 1;
               when others => null;
            end case;
         end loop;

         OS (1) := +I (ctLeftAngleBrackets, "ctLeftAngleBrackets");
         OS (2) := +I (ctRightAngleBrackets, "ctRightAngleBrackets");
         OS (3) := +I (ctAmpersands, "ctAmpersands");
         OS (4) := +I (ctApostrophes, "ctApostrophes");
         OS (5) := +I (ctQuotes, "ctQuotes");

         RP := +SOAP.Types.R (OS, "answer");
      end;

      SOAP.Message.Set_Parameters (R, RP);

      return SOAP.Message.Response.Build (R);
   end SOAP_Count_The_Entities;

   ---------------------------
   -- SOAP_Easy_Struct_Test --
   ---------------------------

   function SOAP_Easy_Struct_Test
     (PL : in SOAP.Message.Payload.Object)
     return AWS.Response.Data
   is
      use SOAP.Types;
      use SOAP.Parameters;

      P  : constant SOAP.Parameters.List := SOAP.Message.Parameters (PL);

      R  : SOAP.Message.Response.Object;
      RP : SOAP.Parameters.List;

   begin
      --  Print SOAP request for the demo

      if not Quiet then
         Text_IO.Put_Line ("SOAP Request easyStructTest");

         Text_IO.Put_Line ("  "
                           & Natural'Image (SOAP.Parameters.Argument_Count (P))
                           & " parameter(s)");
      end if;

      --  Real job start here

      R := SOAP.Message.Response.From (PL);

      declare
         Stooges : constant SOAP.Types.SOAP_Record
           := SOAP.Parameters.Get (P, "stooges");

         V1  : constant Integer := Get (SOAP.Types.V (Stooges, "moe"));
         V2  : constant Integer := Get (SOAP.Types.V (Stooges, "larry"));
         V3  : constant Integer := Get (SOAP.Types.V (Stooges, "curly"));

         Sum : constant Integer := V1 + V2 + V3;

      begin
         RP := +SOAP.Types.I (Sum, "answer");
      end;

      SOAP.Message.Set_Parameters (R, RP);

      return SOAP.Message.Response.Build (R);
   end SOAP_Easy_Struct_Test;

   ---------------------------
   -- SOAP_Echo_Struct_Test --
   ---------------------------

   function SOAP_Echo_Struct_Test
     (PL : in SOAP.Message.Payload.Object)
     return AWS.Response.Data
   is
      use SOAP.Types;
      use SOAP.Parameters;

      P  : constant SOAP.Parameters.List := SOAP.Message.Parameters (PL);

      R  : SOAP.Message.Response.Object;
      RP : SOAP.Parameters.List;

   begin
      --  Print SOAP request for the demo

      if not Quiet then
         Text_IO.Put_Line ("SOAP Request echoStructTest");

         Text_IO.Put_Line ("  "
                           & Natural'Image (SOAP.Parameters.Argument_Count (P))
                           & " parameter(s)");
      end if;

      --  Real job start here

      R := SOAP.Message.Response.From (PL);

      declare
         myStruct : constant SOAP.Types.SOAP_Record
           := SOAP.Parameters.Get (P, "myStruct");
      begin
         RP := +myStruct;
      end;

      SOAP.Message.Set_Parameters (R, RP);

      return SOAP.Message.Response.Build (R);
   end SOAP_Echo_Struct_Test;

   --------------------------
   -- SOAP_Many_Types_Test --
   --------------------------

   function SOAP_Many_Types_Test
     (PL : in SOAP.Message.Payload.Object)
     return AWS.Response.Data
   is
      use SOAP.Types;
      use SOAP.Parameters;

      P  : constant SOAP.Parameters.List := SOAP.Message.Parameters (PL);

      R  : SOAP.Message.Response.Object;
      RP : SOAP.Parameters.List;

   begin
      --  Print SOAP request for the demo

      if not Quiet then
         Text_IO.Put_Line ("SOAP Request manyTypesTest");

         Text_IO.Put_Line ("  "
                           & Natural'Image (SOAP.Parameters.Argument_Count (P))
                           & " parameter(s)");
      end if;

      --  Real job start here

      R := SOAP.Message.Response.From (PL);

      declare
         V1 : constant Object'Class := Argument (P, "num");
         V2 : constant Object'Class := Argument (P, "bool");
         V3 : constant Object'Class := Argument (P, "state");
         V4 : constant Object'Class := Argument (P, "doub");
         V5 : constant Object'Class := Argument (P, "dat");
         V6 : constant Object'Class := Argument (P, "bin");
      begin
         RP := +SOAP.Types.A ((+V1, +V2, +V3, +V4, +V5, +V6), "answer");
      end;

      SOAP.Message.Set_Parameters (R, RP);

      return SOAP.Message.Response.Build (R);
   end SOAP_Many_Types_Test;

   ------------------------------------
   -- SOAP_Moderate_Size_Array_Check --
   ------------------------------------

   function SOAP_Moderate_Size_Array_Check
     (PL : in SOAP.Message.Payload.Object)
     return AWS.Response.Data
   is
      use SOAP.Types;
      use SOAP.Parameters;

      P  : constant SOAP.Parameters.List := SOAP.Message.Parameters (PL);

      R  : SOAP.Message.Response.Object;
      RP : SOAP.Parameters.List;

   begin
      --  Print SOAP request for the demo

      if not Quiet then
         Text_IO.Put_Line ("SOAP Request moderateSizeArrayCheck");

         Text_IO.Put_Line ("  "
                           & Natural'Image (SOAP.Parameters.Argument_Count (P))
                           & " parameter(s)");
      end if;

      --  Real job start here

      R := SOAP.Message.Response.From (PL);

      declare
         A : constant SOAP_Array := SOAP.Parameters.Get (P, "myArray");
         O : constant Object_Set := V (A);

         S1 : constant String := Get (O (O'First).O.all);
         S2 : constant String := Get (O (O'Last).O.all);
      begin
         RP := +S (S1 & S2, "answer");
      end;

      SOAP.Message.Set_Parameters (R, RP);

      return SOAP.Message.Response.Build (R);
   end SOAP_Moderate_Size_Array_Check;

   -----------------------------
   -- SOAP_Nested_Struct_Test --
   -----------------------------

   function SOAP_Nested_Struct_Test
     (PL : in SOAP.Message.Payload.Object)
     return AWS.Response.Data
   is
      use SOAP.Types;
      use SOAP.Parameters;

      P  : constant SOAP.Parameters.List := SOAP.Message.Parameters (PL);

      R  : SOAP.Message.Response.Object;
      RP : SOAP.Parameters.List;

   begin
      --  Print SOAP request for the demo

      if not Quiet then
         Text_IO.Put_Line ("SOAP Request nestedStructTest");

         Text_IO.Put_Line ("  "
                           & Natural'Image (SOAP.Parameters.Argument_Count (P))
                           & " parameter(s)");
      end if;

      --  Real job start here

      R := SOAP.Message.Response.From (PL);

      declare
         S : constant SOAP_Record := SOAP.Parameters.Get (P, "myStruct");

         Y2000 : constant SOAP_Record := Get (V (S, "year2000"));
         M04   : constant SOAP_Record := Get (V (Y2000, "month04"));
         D01   : constant SOAP_Record := Get (V (M04, "day01"));

         V1    : constant Integer := Get (V (D01, "moe"));
         V2    : constant Integer := Get (V (D01, "larry"));
         V3    : constant Integer := Get (V (D01, "curly"));

      begin
         RP := +I (V1 + V2 + V3, "answer");
      end;

      SOAP.Message.Set_Parameters (R, RP);

      return SOAP.Message.Response.Build (R);
   end SOAP_Nested_Struct_Test;

   ------------------------------------
   -- SOAP_Simple_Struct_Return_Test --
   ------------------------------------

   function SOAP_Simple_Struct_Return_Test
     (PL : in SOAP.Message.Payload.Object)
     return AWS.Response.Data
   is
      use SOAP.Types;
      use SOAP.Parameters;

      P  : constant SOAP.Parameters.List := SOAP.Message.Parameters (PL);

      R  : SOAP.Message.Response.Object;
      RP : SOAP.Parameters.List;

   begin
      --  Print SOAP request for the demo

      if not Quiet then
         Text_IO.Put_Line ("SOAP Request simpleStructReturnTest");

         Text_IO.Put_Line ("  "
                           & Natural'Image (SOAP.Parameters.Argument_Count (P))
                           & " parameter(s)");
      end if;

      --  Real job start here

      R := SOAP.Message.Response.From (PL);

      declare
         N : constant Integer := SOAP.Parameters.Get (P, "myNumber");

         V1 : constant Integer := N * 10;
         V2 : constant Integer := N * 100;
         V3 : constant Integer := N * 1000;

      begin
         RP := +SOAP.Types.R (Object_Set'(+I (V1, "times10"),
                                          +I (V2, "times100"),
                                          +I (V3, "times1000")),
                              "answer");
      end;

      SOAP.Message.Set_Parameters (R, RP);

      return SOAP.Message.Response.Build (R);
   end SOAP_Simple_Struct_Return_Test;

   ------------------------
   -- SOAP_Which_Toolkit --
   ------------------------

   function SOAP_Which_Toolkit
     (PL : in SOAP.Message.Payload.Object)
     return AWS.Response.Data
   is
      use SOAP.Types;
      use SOAP.Parameters;

      P  : constant SOAP.Parameters.List := SOAP.Message.Parameters (PL);

      R  : SOAP.Message.Response.Object;
      RP : SOAP.Parameters.List;

   begin
      --  Print SOAP request for the demo

      if not Quiet then
         Text_IO.Put_Line ("SOAP Request withToolkit");

         Text_IO.Put_Line ("  "
                           & Natural'Image (SOAP.Parameters.Argument_Count (P))
                           & " parameter(s)");
      end if;

      --  Real job start here

      R := SOAP.Message.Response.From (PL);

      RP := +SOAP.Types.R
        (Object_Set'(+S ("http://libre.act-europe.fr/", "toolkitDocsUrl"),
                     +S ("AWS/SOAP (Ada Web Server)", "toolkitName"),
                     +S (AWS.Version & '.' & SOAP.Version, "toolkitVersion"),
                     +S ("Windows", "toolkitOperatingSystem")),
         "answer");

      SOAP.Message.Set_Parameters (R, RP);

      return SOAP.Message.Response.Build (R);
   end SOAP_Which_Toolkit;

begin
   if Command_Line.Argument_Count = 1
     and then Command_Line.Argument (1) = "-t"
   then
      Quiet := False;
   end if;

   AWS.Server.Start (WS, "SOAP Validation Suite",
                     Max_Connection => 5,
                     Callback       => CB'Unrestricted_Access);

   Text_IO.Put_Line ("SOAP SVS - hit a key to exit");

   --  Wait a charcter to exit

   declare
      C : Character;
   begin
      Text_IO.Get_Immediate (C);
   end;

   AWS.Server.Shutdown (WS);
end SOAP_SVS;
