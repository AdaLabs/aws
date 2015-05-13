------------------------------------------------------------------------------
--                              Ada Web Server                              --
--                                                                          --
--                     Copyright (C) 2000-2015, AdaCore                     --
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

pragma Ada_2012;

with Ada.Characters.Handling;
with Ada.Exceptions;
with Ada.Strings.Fixed;

with AWS.Client.XML.Input_Sources;

with DOM.Core.Nodes;
with Input_Sources.Strings;
with Sax.Readers;
with Unicode.CES.Utf8;

with SOAP.Message.Reader;
with SOAP.Message.Response.Error;
with SOAP.Name_Space;
with SOAP.Types.Untyped;
with SOAP.Utils;
with SOAP.XML;

package body SOAP.Message.XML is

   use Ada;
   use DOM.Core.Nodes;
   use SOAP.Message.Reader;

   NL : constant String := ASCII.CR & ASCII.LF;

   Max_Object_Size : constant := 2_048;
   --  This is the maximum number of items in a record or an array supported
   --  by this implementation.

   XML_Header : constant String := "<?xml version='1.0' encoding='UTF-8'?>";

   --  Alternate URLs
   URL_xsd    : constant String := "http://www.w3.org/1999/XMLSchema";
   URL_xsi    : constant String := "http://www.w3.org/1999/XMLSchema-instance";

   type Type_State is
     (Void, T_Undefined, T_Any_Type,
      T_Int, T_Float, T_Double, T_Long, T_Short, T_Byte,
      T_Unsigned_Long, T_Unsigned_Int, T_Unsigned_Short, T_Unsigned_Byte,
      T_String, T_Boolean, T_Time_Instant, T_Date_Time,
      T_Base64, T_Base64_Bin);

   type Namespaces is record
      xsd   : SOAP.Name_Space.Object := SOAP.Name_Space.XSD;
      xsi   : SOAP.Name_Space.Object := SOAP.Name_Space.XSI;
      enc   : SOAP.Name_Space.Object := SOAP.Name_Space.SOAPENC;
      env   : SOAP.Name_Space.Object := SOAP.Name_Space.SOAPENV;
      User  : NS_Set;
      Index : Natural := 0;
   end record;

   type State is record
      Name_Space   : SOAP.Name_Space.Object;
      Wrapper_Name : Unbounded_String;
      Parameters   : SOAP.Parameters.List;
      A_State      : Type_State := Void;
      NS           : Namespaces;
      Strict       : Boolean    := True;
      Style        : WSDL.Schema.Binding_Style := WSDL.Schema.RPC;
      Schema       : WSDL.Schema.Definition;
      Enclosing    : Unbounded_String; -- enclosing element name (record)
   end record;

   function To_Type
     (Type_Name : String;
      NS        : Namespaces;
      Schema    : WSDL.Schema.Definition)
      return Type_State;
   --  Given the Type_Name and the namespaces return the proper type

   procedure Load_XML
     (Input : in out Input_Sources.Input_Source'Class;
      S     : out State);
   --  Load XML document, set State and ensure the document is freed when an
   --  exception occurs. The Input source is closed before returning.

   procedure Parse_Namespaces
     (N  : DOM.Core.Node;
      NS : in out Namespaces);
   --  Read namespaces from node and set NS accordingly

   function Get_Namespace_Value
     (NS   : Namespaces;
      Name : String) return String;
   --  Returns the user's namspace value for the given namespace name

   function Get_Namespace_Object
     (NS : Namespaces; Name : String) return SOAP.Name_Space.Object;
   --  Returns the user namespace for the given name

   procedure Parse_Document
     (N : DOM.Core.Node;
      S : in out State);

   procedure Parse_Envelope
     (N : DOM.Core.Node;
      S : in out State);

   procedure Parse_Header
     (N : DOM.Core.Node;
      S : in out State);

   procedure Parse_Body
     (N : DOM.Core.Node;
      S : in out State);

   procedure Parse_Wrapper
     (N : DOM.Core.Node;
      S : in out State);

   --  Parse routines for specific types

   function Parse_Any_Type
     (Name      : String;
      Type_Name : String;
      N         : DOM.Core.Node) return Types.Object'Class;

   function Parse_Long
     (Name      : String;
      Type_Name : String;
      N         : DOM.Core.Node) return Types.Object'Class;

   function Parse_Int
     (Name      : String;
      Type_Name : String;
      N         : DOM.Core.Node) return Types.Object'Class;

   function Parse_Short
     (Name      : String;
      Type_Name : String;
      N         : DOM.Core.Node) return Types.Object'Class;

   function Parse_Byte
     (Name      : String;
      Type_Name : String;
      N         : DOM.Core.Node) return Types.Object'Class;

   function Parse_Float
     (Name      : String;
      Type_Name : String;
      N         : DOM.Core.Node) return Types.Object'Class;

   function Parse_Double
     (Name      : String;
      Type_Name : String;
      N         : DOM.Core.Node) return Types.Object'Class;

   function Parse_String
     (Name      : String;
      Type_Name : String;
      N         : DOM.Core.Node) return Types.Object'Class;

   function Parse_Boolean
     (Name      : String;
      Type_Name : String;
      N         : DOM.Core.Node) return Types.Object'Class;

   function Parse_Base64
     (Name      : String;
      Type_Name : String;
      N         : DOM.Core.Node) return Types.Object'Class;

   function Parse_Unsigned_Long
     (Name      : String;
      Type_Name : String;
      N         : DOM.Core.Node) return Types.Object'Class;

   function Parse_Unsigned_Int
     (Name      : String;
      Type_Name : String;
      N         : DOM.Core.Node) return Types.Object'Class;

   function Parse_Unsigned_Short
     (Name      : String;
      Type_Name : String;
      N         : DOM.Core.Node) return Types.Object'Class;

   function Parse_Unsigned_Byte
     (Name      : String;
      Type_Name : String;
      N         : DOM.Core.Node) return Types.Object'Class;

   function Parse_Untyped
     (Name : String;
      N    : DOM.Core.Node) return Types.Object'Class;
   --  Parse a node whose type is unknown. This is used to workaround the fact
   --  that AWS parser is not aware of the WSDL schema.

   function Parse_Time_Instant
     (Name      : String;
      Type_Name : String;
      N         : DOM.Core.Node) return Types.Object'Class;

   function Parse_Param
     (N : DOM.Core.Node;
      S : in out State) return Types.Object'Class;

   function Parse_Array
     (Name : String;
      N    : DOM.Core.Node;
      S    : in out State) return Types.Object'Class;

   function Parse_Record
     (Name : String;
      N    : DOM.Core.Node;
      S    : in out State) return Types.Object'Class;

   function Parse_Enumeration
     (Name : String;
      N    : DOM.Core.Node) return Types.Object'Class;

   procedure Error (Node : DOM.Core.Node; Message : String) with No_Return;
   --  Raises SOAP_Error with the Message as exception message

   type Parse_Type is access
     function (Name      : String;
               Type_Name : String;
               N         : DOM.Core.Node) return Types.Object'Class;

   type Type_Handler is record
      Name    : access constant String;
      Handler : Parse_Type;
      Encoded : Boolean; --  True if based on soap-enc namespaces
   end record;

   Handlers : constant array (Type_State) of Type_Handler :=
                (Void           =>
                   (null, null, False),
                 T_Undefined    =>
                   (Types.XML_Undefined'Access, null, False),
                 T_Any_Type      =>
                   (Types.XML_Any_Type'Access, Parse_Any_Type'Access, False),
                 T_Long          =>
                   (Types.XML_Long'Access, Parse_Long'Access, False),
                 T_Int            =>
                   (Types.XML_Int'Access, Parse_Int'Access, False),
                 T_Short          =>
                   (Types.XML_Short'Access, Parse_Short'Access, False),
                 T_Byte           =>
                   (Types.XML_Byte'Access, Parse_Byte'Access, False),
                 T_Float          =>
                   (Types.XML_Float'Access, Parse_Float'Access, False),
                 T_Double         =>
                   (Types.XML_Double'Access, Parse_Double'Access, False),
                 T_String         =>
                   (Types.XML_String'Access, Parse_String'Access, False),
                 T_Boolean        =>
                   (Types.XML_Boolean'Access, Parse_Boolean'Access, False),
                 T_Base64         =>
                   (Types.XML_Base64'Access, Parse_Base64'Access, True),
                 T_Base64_Bin     =>
                   (Types.XML_Base64_Binary'Access, Parse_Base64'Access, True),
                 T_Unsigned_Long  =>
                   (Types.XML_Unsigned_Long'Access,
                    Parse_Unsigned_Long'Access, False),
                 T_Unsigned_Int   =>
                   (Types.XML_Unsigned_Int'Access,
                    Parse_Unsigned_Int'Access, False),
                 T_Unsigned_Short =>
                   (Types.XML_Unsigned_Short'Access,
                    Parse_Unsigned_Short'Access, False),
                 T_Unsigned_Byte  =>
                   (Types.XML_Unsigned_Byte'Access,
                    Parse_Unsigned_Byte'Access, False),
                 T_Date_Time   =>
                   (Types.XML_Date_Time'Access,
                    Parse_Time_Instant'Access, False),
                 T_Time_Instant   =>
                   (Types.XML_Time_Instant'Access,
                    Parse_Time_Instant'Access, False));

   -----------
   -- Error --
   -----------

   procedure Error (Node : DOM.Core.Node; Message : String) is
      Name : constant String := Local_Name (Node);
   begin
      raise SOAP_Error with Name & " - " & Message;
   end Error;

   --------------------------
   -- Get_Namespace_Object --
   --------------------------

   function Get_Namespace_Object
     (NS : Namespaces; Name : String) return SOAP.Name_Space.Object is
   begin
      for K in 1 .. NS.Index loop
         if SOAP.Name_Space.Name (NS.User (K)) = Name then
            return NS.User (K);
         end if;
      end loop;

      return SOAP.Name_Space.No_Name_Space;
   end Get_Namespace_Object;

   -------------------------
   -- Get_Namespace_Value --
   -------------------------

   function Get_Namespace_Value
     (NS   : Namespaces;
      Name : String) return String is
   begin
      for K in 1 .. NS.Index loop
         if SOAP.Name_Space.Name (NS.User (K)) = Name then
            return SOAP.Name_Space.Value (NS.User (K));
         end if;
      end loop;

      return "";
   end Get_Namespace_Value;

   -----------
   -- Image --
   -----------

   function Image
     (O      : Object'Class;
      Schema : WSDL.Schema.Definition := WSDL.Schema.Empty) return String is
   begin
      return To_String (XML.Image (O, Schema));
   end Image;

   -----------
   -- Image --
   -----------

   function Image
     (O      : Object'Class;
      Schema : WSDL.Schema.Definition :=
                 WSDL.Schema.Empty) return Unbounded_String
   is
      Message_Body : Unbounded_String;

      function Get_NS (URL, Default : String) return String;
      --  Returns the name-space as defined in the schema for the given URL or
      --  default if not found.

      ------------
      -- Get_NS --
      ------------

      function Get_NS (URL, Default : String) return String is
      begin
         if Schema.Contains (URL) then
            return "xmlns:" & Schema (URL) & "=""" & URL & '"';
         else
            return Default;
         end if;
      end Get_NS;

      --  Name spaces

      NS_Enc     : constant SOAP.Name_Space.Object :=
                     SOAP.Name_Space.Create
                       ("encodingStyle",
                        SOAP.Name_Space.SOAPENC_URL,
                        Prefix => SOAP.Name_Space.Name (O.env));

      SOAPENV    : constant String :=
                     SOAP.Name_Space.Name (O.env);

      Start_Env  : constant String := "<" & SOAPENV & ":Envelope";
      End_Env    : constant String := "</" & SOAPENV & ":Envelope>";
      Start_Body : constant String := "<" & SOAPENV & ":Body";
      End_Body   : constant String := "</" & SOAPENV & ":Body>";

   begin
      --  Header

      Append (Message_Body, XML_Header & NL);

      --  Add environment

      Append
        (Message_Body,
         Start_Env
         & ' ' & SOAP.Name_Space.Image (NS_Enc)
         & ' '
         & Get_NS (SOAP.Name_Space.SOAPENC_URL, SOAP.Name_Space.Image (O.enc))
         & ' '
         & Get_NS (SOAP.Name_Space.SOAPENV_URL, SOAP.Name_Space.Image (O.env))
         & ' '
         & Get_NS (SOAP.Name_Space.XSD_URL, SOAP.Name_Space.Image (O.xsd))
         & ' '
         & Get_NS (SOAP.Name_Space.XSI_URL, SOAP.Name_Space.Image (O.xsi))
         & '>' & NL);

      --  Body

      Append (Message_Body, Start_Body);

      --  Wrapper

      Append (Message_Body, Message.XML_Image (O, Schema));

      --  End of Body and Envelope

      Append (Message_Body, End_Body & NL);
      Append (Message_Body, End_Env & NL);

      return Message_Body;
   end Image;

   ------------------
   -- Load_Payload --
   ------------------

   function Load_Payload
     (XML      : aliased String;
      Envelope : Boolean := True;
      Schema   : WSDL.Schema.Definition := WSDL.Schema.Empty)
      return Message.Payload.Object
   is
      use Input_Sources.Strings;
      Source : String_Input;
      S      : State;
   begin
      Open (XML'Unchecked_Access,
            Unicode.CES.Utf8.Utf8_Encoding,
            Source);

      S.Strict := Envelope;
      S.Schema := Schema;
      S.Style  := WSDL.Schema.Get_Binding_Style (Schema);

      Load_XML (Source, S);
      Close (Source);

      return Message.Payload.Build
        (To_String (S.Wrapper_Name), S.Parameters, S.Name_Space);
   end Load_Payload;

   function Load_Payload
     (XML      : Unbounded_String;
      Envelope : Boolean := True;
      Schema   : WSDL.Schema.Definition := WSDL.Schema.Empty)
      return Message.Payload.Object
   is
      XML_Str : String_Access := new String (1 .. Length (XML));
   begin
      for I in 1 .. Length (XML) loop
         XML_Str (I) := Element (XML, I);
      end loop;

      return O : constant Message.Payload.Object :=
                   Load_Payload (XML_Str.all, Envelope, Schema)
      do
         Free (XML_Str);
      end return;
   exception
      when others =>
         Free (XML_Str);
         raise;
   end Load_Payload;

   -------------------
   -- Load_Response --
   -------------------

   function Load_Response
     (Connection : AWS.Client.HTTP_Connection;
      Envelope   : Boolean := True;
      Schema     : WSDL.Schema.Definition := WSDL.Schema.Empty)
      return Message.Response.Object'Class
   is
      use AWS.Client.XML.Input_Sources;

      Source : HTTP_Input;
      S      : State;

   begin
      Create (Connection, Source);

      S.Strict := Envelope;
      S.Schema := Schema;
      S.Style  := WSDL.Schema.Get_Binding_Style (Schema);

      Load_XML (Source, S);
      Close (Source);

      if SOAP.Parameters.Exist (S.Parameters, "faultcode") then
         return Message.Response.Error.Build
           (Faultcode   =>
              Message.Response.Error.Faultcode
               (String'(SOAP.Parameters.Get (S.Parameters, "faultcode"))),
            Faultstring => SOAP.Parameters.Get (S.Parameters, "faultstring"));
      else
         return Message.Response.Object'
           (Message.Object'(S.Name_Space, S.Wrapper_Name, S.Parameters,
            S.NS.xsd, S.NS.xsi, S.NS.enc, S.NS.env, S.NS.User, S.NS.Index)
            with null record);
      end if;

   exception
      when E : others =>
         return Message.Response.Error.Build
           (Faultcode   => Message.Response.Error.Client,
            Faultstring => Exceptions.Exception_Message (E));
   end Load_Response;

   function Load_Response
     (XML      : aliased String;
      Envelope : Boolean := True;
      Schema   : WSDL.Schema.Definition := WSDL.Schema.Empty)
      return Message.Response.Object'Class
   is
      use Input_Sources.Strings;

      Source : String_Input;
      S      : State;

   begin
      Open (XML'Unchecked_Access,
            Unicode.CES.Utf8.Utf8_Encoding,
            Source);

      S.Strict := Envelope;
      S.Schema := Schema;
      S.Style  := WSDL.Schema.Get_Binding_Style (Schema);

      Load_XML (Source, S);
      Close (Source);

      if SOAP.Parameters.Exist (S.Parameters, "faultcode") then
         return Message.Response.Error.Build
           (Faultcode   =>
              Message.Response.Error.Faultcode
               (String'(SOAP.Parameters.Get (S.Parameters, "faultcode"))),
            Faultstring => SOAP.Parameters.Get (S.Parameters, "faultstring"));
      else
         return Message.Response.Object'
           (Message.Object'(S.Name_Space, S.Wrapper_Name, S.Parameters,
            S.NS.xsd, S.NS.xsi, S.NS.enc, S.NS.env, S.NS.User, S.NS.Index)
            with null record);
      end if;

   exception
      when E : others =>
         return Message.Response.Error.Build
           (Faultcode   => Message.Response.Error.Client,
            Faultstring => Exceptions.Exception_Message (E));
   end Load_Response;

   function Load_Response
     (XML      : Unbounded_String;
      Envelope : Boolean := True;
      Schema   : WSDL.Schema.Definition := WSDL.Schema.Empty)
      return Message.Response.Object'Class
   is
      S : String_Access := new String (1 .. Length (XML));
   begin
      --  Copy XML content to local S string
      for I in 1 .. Length (XML) loop
         S (I) := Element (XML, I);
      end loop;

      declare
         Result : constant Message.Response.Object'Class :=
                    Load_Response (S.all, Envelope, Schema);
      begin
         Free (S);
         return Result;
      end;
   end Load_Response;

   --------------
   -- Load_XML --
   --------------

   procedure Load_XML
     (Input : in out Input_Sources.Input_Source'Class;
      S     : out State)
   is
      Reader : Tree_Reader;
      Doc    : DOM.Core.Document;
   begin
      --  If True, xmlns:* attributes will be reported in Start_Element
      Set_Feature (Reader, Sax.Readers.Namespace_Prefixes_Feature, True);
      Set_Feature (Reader, Sax.Readers.Validation_Feature, False);

      Parse (Reader, Input);

      Doc := Get_Tree (Reader);

      Parse_Document (Doc, S);

      Free (Doc);

   exception
      when others =>
         Doc := Get_Tree (Reader);
         Free (Doc);
         raise;
   end Load_XML;

   --------------------
   -- Parse_Any_Type --
   --------------------

   function Parse_Any_Type
     (Name      : String;
      Type_Name : String;
      N         : DOM.Core.Node) return Types.Object'Class is
   begin
      --  ??? We have no type information, in this implementation we map the
      --  value into a xsd:string.
      return Parse_String (Name, Type_Name, N);
   end Parse_Any_Type;

   -----------------
   -- Parse_Array --
   -----------------

   function Parse_Array
     (Name : String;
      N    : DOM.Core.Node;
      S    : in out State) return Types.Object'Class
   is
      use SOAP.Types;
      use type DOM.Core.Node;

      function Item_Type (Name : String) return String with Inline;
      --  Returns the array's item type, remove [] if present

      ---------------
      -- Item_Type --
      ---------------

      function Item_Type (Name : String) return String is
         N : constant Positive := Strings.Fixed.Index (Name, "[");
      begin
         return Name (Name'First .. N - 1);
      end Item_Type;

      LS    : constant State := S;

      OS    : Types.Object_Set (1 .. Max_Object_Size);
      K     : Natural := 0;

      Field : DOM.Core.Node;

      Atts  : constant DOM.Core.Named_Node_Map := Attributes (N);

   begin
      Parse_Namespaces (N, S.NS);

      declare
         A_Name    : constant String :=
                       SOAP.Name_Space.Name (S.NS.enc) & ":arrayType";
         --  Attribute name

         Type_Name : constant String :=
                       Item_Type (Node_Value (Get_Named_Item (Atts, A_Name)));

         A_Type    : constant Type_State :=
                       To_Type (Type_Name, S.NS, S.Schema);
      begin
         Field := SOAP.XML.First_Child (N);

         --  Set state for the enclosing elements

         S.Enclosing := To_Unbounded_String (Name);
         S.A_State := A_Type;

         while Field /= null loop
            K := K + 1;

            OS (K) := +Parse_Param (Field, S);

            Field := Next_Sibling (Field);
         end loop;

         --  Restore state

         S.A_State := LS.A_State;
         S.Enclosing := LS.Enclosing;

         return Types.A (OS (1 .. K), Name, Type_Name);
      end;
   end Parse_Array;

   ------------------
   -- Parse_Base64 --
   ------------------

   function Parse_Base64
     (Name      : String;
      Type_Name : String;
      N         : DOM.Core.Node) return Types.Object'Class
   is
      use type DOM.Core.Node;

      Value : DOM.Core.Node;
   begin
      Normalize (N);
      Value := First_Child (N);

      if Value = null then
         --  No node found, this is an empty Base64 content
         return Types.B64 ("", Name, Type_Name);

      else
         return Types.B64 (Node_Value (Value), Name, Type_Name);
      end if;
   end Parse_Base64;

   ----------------
   -- Parse_Body --
   ----------------

   procedure Parse_Body (N : DOM.Core.Node; S : in out State) is
      use type WSDL.Schema.Binding_Style;
   begin
      Parse_Namespaces (N, S.NS);

      if S.Style = WSDL.Schema.RPC then
         Parse_Wrapper (SOAP.XML.First_Child (N), S);

      else
         --  When on Document style the actual procedure to call is given
         --  by the signature of the procedure. That is the set of procedure
         --  parameter name give the procedure to call.
         --
         --  So two calls cannot have the same signatures, that is why such
         --  WSDL are using a parameter based on the actual call to be done.
         --
         --  We should compute the signature first as we need to know the
         --  actual procedure name to be able to get the encoding style
         --  (literal/encoded). We also need to know the procedure name as
         --  it is used as a prefix to the parameters to get the type in the
         --  schema.

         Compute_Signature : declare
            use type DOM.Core.Node;
            P         : DOM.Core.Node := SOAP.XML.First_Child (N);
            Signature : Unbounded_String;
         begin
            while P /= null loop
               if Signature /= Null_Unbounded_String then
                  Append (Signature, ":");
               end if;

               Append (Signature, Utils.No_NS (Node_Name (P)));

               P := SOAP.XML.Next_Sibling (P);
            end loop;

            --  Get SOAP call for this specific signature

            S.Wrapper_Name :=
              To_Unbounded_String
                (WSDL.Schema.Get_Call_For_Signature
                   (S.Schema, To_String (Signature)));
         end Compute_Signature;

         declare
            use SOAP.Parameters;
            use type DOM.Core.Node;
            P : DOM.Core.Node := SOAP.XML.First_Child (N);
         begin
            while P /= null loop
               S.Parameters := S.Parameters & Parse_Param (P, S);
               P := SOAP.XML.Next_Sibling (P);
            end loop;
         end;
      end if;
   end Parse_Body;

   -------------------
   -- Parse_Boolean --
   -------------------

   function Parse_Boolean
     (Name      : String;
      Type_Name : String;
      N         : DOM.Core.Node) return Types.Object'Class
   is
      Value : constant DOM.Core.Node := First_Child (N);
   begin
      if Node_Value (Value) = "1"
        or else Node_Value (Value) = "true"
        or else Node_Value (Value) = "TRUE"
      then
         return Types.B (True, Name);
      else
         --  ??? we should check for wrong boolean value
         return Types.B (False, Name, Type_Name);
      end if;
   end Parse_Boolean;

   ----------------
   -- Parse_Byte --
   ----------------

   function Parse_Byte
     (Name      : String;
      Type_Name : String;
      N         : DOM.Core.Node) return Types.Object'Class
   is
      Value : constant DOM.Core.Node := First_Child (N);
   begin
      return Types.B (Types.Byte'Value (Node_Value (Value)), Name, Type_Name);
   end Parse_Byte;

   --------------------
   -- Parse_Document --
   --------------------

   procedure Parse_Document (N : DOM.Core.Node; S : in out State) is
      NL : constant DOM.Core.Node_List := Child_Nodes (N);
   begin
      if Length (NL) = 1 then
         Parse_Envelope (SOAP.XML.First_Child (N), S);
      else
         Error (N, "Document must have a single node, found "
                & Natural'Image (Length (NL)));
      end if;
   end Parse_Document;

   ------------------
   -- Parse_Double --
   ------------------

   function Parse_Double
     (Name      : String;
      Type_Name : String;
      N         : DOM.Core.Node) return Types.Object'Class
   is
      Value : constant DOM.Core.Node := First_Child (N);
   begin
      return Types.D (Long_Float'Value (Node_Value (Value)), Name, Type_Name);
   end Parse_Double;

   -----------------------
   -- Parse_Enumeration --
   -----------------------

   function Parse_Enumeration
     (Name : String;
      N    : DOM.Core.Node) return Types.Object'Class is
   begin
      return Types.E
        (Node_Value (First_Child (N)),
         Utils.No_NS (SOAP.XML.Get_Attr_Value (N, "type")),
         Name);
   end Parse_Enumeration;

   --------------------
   -- Parse_Envelope --
   --------------------

   procedure Parse_Envelope (N : DOM.Core.Node; S : in out State) is
      NL : constant DOM.Core.Node_List := Child_Nodes (N);
   begin
      Parse_Namespaces (N, S.NS);

      if Local_Name (N) /= "Envelope" then
         if S.Strict then
            Error
              (N,
               "Root tag local name have to be 'Envelope', but '"
               & Local_Name (N) & "' found.");
         else
            Parse_Wrapper (N, S);
         end if;

      elsif Length (NL) = 1 then
         --  This must be the body
         Parse_Body (SOAP.XML.First_Child (N), S);

      elsif Length (NL) = 2 then
         --  The first child must the header tag
         Parse_Header (SOAP.XML.First_Child (N), S);

         --  The second child must be the body
         Parse_Body (SOAP.XML.Next_Sibling (First_Child (N)), S);
      else
         Error (N, "Envelope must have at most two nodes, found "
                & Natural'Image (Length (NL)));
      end if;
   end Parse_Envelope;

   -----------------
   -- Parse_Float --
   -----------------

   function Parse_Float
     (Name      : String;
      Type_Name : String;
      N         : DOM.Core.Node) return Types.Object'Class
   is
      Value : constant DOM.Core.Node := First_Child (N);
   begin
      return Types.F (Float'Value (Node_Value (Value)), Name, Type_Name);
   end Parse_Float;

   ------------------
   -- Parse_Header --
   ------------------

   procedure Parse_Header (N : DOM.Core.Node; S : in out State) is
      pragma Unreferenced (S);
      Name : constant String := Local_Name (N);
   begin
      if Ada.Characters.Handling.To_Lower (Name) /= "header" then
         Error (N, "Header node expected, found " & Name);
      end if;
   end Parse_Header;

   ---------------
   -- Parse_Int --
   ---------------

   function Parse_Int
     (Name      : String;
      Type_Name : String;
      N         : DOM.Core.Node) return Types.Object'Class
   is
      Value : constant DOM.Core.Node := First_Child (N);
   begin
      return Types.I (Integer'Value (Node_Value (Value)), Name, Type_Name);
   end Parse_Int;

   ----------------
   -- Parse_Long --
   ----------------

   function Parse_Long
     (Name      : String;
      Type_Name : String;
      N         : DOM.Core.Node) return Types.Object'Class
   is
      Value : constant DOM.Core.Node := First_Child (N);
   begin
      return Types.L (Types.Long'Value (Node_Value (Value)), Name, Type_Name);
   end Parse_Long;

   ----------------------
   -- Parse_Namespaces --
   ----------------------

   procedure Parse_Namespaces
     (N  : DOM.Core.Node;
      NS : in out Namespaces)
   is
      Atts : constant DOM.Core.Named_Node_Map := Attributes (N);
   begin
      for K in 0 .. Length (Atts) - 1 loop
         declare
            N     : constant DOM.Core.Node := Item (Atts, K);
            Name  : constant String        := Node_Name (N);
            Value : constant String        := Node_Value (N);
         begin
            if Utils.NS (Name) = "xmlns" then
               if Value = URL_xsd
                 or else Value = SOAP.Name_Space.XSD_URL
               then
                  NS.xsd := SOAP.Name_Space.Create (Utils.No_NS (Name), Value);

               elsif Value = URL_xsi
                 or else Value = SOAP.Name_Space.XSI_URL
               then
                  NS.xsi := SOAP.Name_Space.Create (Utils.No_NS (Name), Value);

               elsif Value = SOAP.Name_Space.SOAPENC_URL then
                  NS.enc := SOAP.Name_Space.Create (Utils.No_NS (Name), Value);

               elsif Value = SOAP.Name_Space.SOAPENV_URL then
                  NS.env := SOAP.Name_Space.Create (Utils.No_NS (Name), Value);

               elsif NS.Index < NS.User'Last then
                  NS.Index := NS.Index + 1;
                  NS.User (NS.Index) :=
                    SOAP.Name_Space.Create (Utils.No_NS (Name), Value);
               end if;
            end if;
         end;
      end loop;
   end Parse_Namespaces;

   -----------------
   -- Parse_Param --
   -----------------

   function Parse_Param
     (N : DOM.Core.Node;
      S : in out State) return Types.Object'Class
   is
      use type DOM.Core.Node;
      use type DOM.Core.Node_Types;
      use type SOAP.Types.Encoding_Style;

      function Is_Array return Boolean;
      --  Returns True if N is an array node

      function With_NS
        (O  : Types.Object'Class;
         NS : SOAP.Name_Space.Object) return Types.Object'Class;
      --  Retruns O with the associated name-space

      Name     : constant String := Local_Name (N);
      Key      : constant String :=
                   (if S.Enclosing /= Null_Unbounded_String
                    then To_String (S.Enclosing) & "." & Name
                    else Name);
      Encoding : constant SOAP.Types.Encoding_Style :=
                   WSDL.Schema.Get_Encoding_Style
                     (S.Schema, To_String (S.Wrapper_Name));

      Ref  : constant DOM.Core.Node           := SOAP.XML.Get_Ref (N);
      Atts : constant DOM.Core.Named_Node_Map := Attributes (Ref);

      --------------
      -- Is_Array --
      --------------

      function Is_Array return Boolean is
         XSI_Type : constant DOM.Core.Node :=
                      Get_Named_Item
                        (Atts, SOAP.Name_Space.Name (S.NS.xsi) & ":type");
         SOAP_Enc : constant DOM.Core.Node :=
                      Get_Named_Item
                        (Atts,
                         SOAP.Name_Space.Name (S.NS.enc) & ":arrayType");
      begin
         return
         --  Either we have xsi:type="soapenc:Array"
           (XSI_Type /= null
            and then Utils.No_NS (Node_Value (XSI_Type)) = "Array")
           or else
         --  or soapenc:arrayType="..."
             SOAP_Enc /= null;
      end Is_Array;

      -------------
      -- With_NS --
      -------------

      function With_NS
        (O  : Types.Object'Class;
         NS : SOAP.Name_Space.Object) return Types.Object'Class
      is
         use type SOAP.Name_Space.Object;
         L : Types.Object'Class := O;
      begin
         if NS /= SOAP.Name_Space.No_Name_Space then
            Types.Set_Name_Space (L, NS);
         end if;
         return L;
      end With_NS;

      S_Type   : constant DOM.Core.Node := Get_Named_Item (Atts, "type");
      XSI_Type : DOM.Core.Node;
      xsd      : Unbounded_String;
      NS       : SOAP.Name_Space.Object := SOAP.Name_Space.No_Name_Space;

   begin
      Parse_Namespaces (Ref, S.NS);

      if  Encoding = WSDL.Schema.Encoded then
         XSI_Type :=
           Get_Named_Item (Atts, SOAP.Name_Space.Name (S.NS.xsi) & ":type");

         if XSI_Type /= null then
            xsd := To_Unbounded_String (Node_Value (XSI_Type));
         end if;

      else
         if S.Schema.Contains (Key) then
            xsd := To_Unbounded_String (S.Schema (Key));
         end if;
      end if;

      NS := Get_Namespace_Object (S.NS, Utils.NS (To_String (xsd)));

      if To_String (S.Wrapper_Name) = "Fault" then
         return Parse_String (Name, Types.XML_String, Ref);

      elsif Is_Array then
         return Parse_Array (Name, Ref, S);

      else
         if XSI_Type = null
           and then xsd = Null_Unbounded_String
           and then S.A_State in Void .. T_Undefined
         then
            --  No xsi:type attribute found

            if Get_Named_Item
              (Atts, SOAP.Name_Space.Name (S.NS.xsi) & ":null") /= null
            then
               return Types.N (Name);

            elsif S_Type /= null
              and then First_Child (Ref).Node_Type = DOM.Core.Text_Node
            then
               --  Not xsi:type but a type information, the child being a text
               --  node, this is an enumeration.

               return Parse_Enumeration (Name, Ref);

            elsif First_Child (Ref) = null then
               --  We have an emtpy node, return an empty string in this case
               --  otherwise we will create an empty record in the else section
               --  below.

               return Types.Untyped.S ("", Name);

            elsif First_Child (Ref).Node_Type = DOM.Core.Text_Node then
               --  No xsi:type and no type information. Children are some kind
               --  of text data, so this is a data node with no type
               --  information. Note that this code is to workaround an
               --  interoperability problem found with gSOAP and Microsoft SOAP
               --  implementation based on WSDL were the type information is
               --  not provided into the payload but only on the WSDL file. As
               --  AWS/SOAP parser is not WSDL compliant at this point we
               --  record such type as undefined. Later the value will be
               --  converted to to right type when read by one of the
               --  Types.Get routine. Note that this code is only there to
               --  parse data received from a SOAP server. AWS/SOAP always send
               --  type information into the payload.

               return Parse_Untyped (Name, Ref);

            else
               --  This is a type defined in a schema, either a SOAP record
               --  or an enumeration, enumerations will be checked into
               --  Parse record.
               --  This is a SOAP record, we have no attribute and no
               --  type defined. We have a single tag "<name>" which can
               --  only be the start or a record.

               return Parse_Record (Name, Ref, S);
            end if;

         else
            declare
               S_xsd  : constant String     := To_String (xsd);
               S_Type : constant Type_State :=
                          To_Type (S_xsd, S.NS, S.Schema);
            begin
               if S_Type = T_Undefined then
                  --  Not a known basic type, let's try to parse a
                  --  record object. This implemtation does not
                  --  support schema so there is no way to check
                  --  for the real type here.

                  return Parse_Record (Name, Ref, S);

               else
                  return With_NS
                    (Handlers (S_Type).Handler (Name, S_xsd, Ref), NS);
               end if;
            end;
         end if;
      end if;
   end Parse_Param;

   ------------------
   -- Parse_Record --
   ------------------

   function Parse_Record
     (Name : String;
      N    : DOM.Core.Node;
      S    : in out State) return Types.Object'Class
   is
      use SOAP.Types;
      use type DOM.Core.Node;
      use type DOM.Core.Node_Types;
      use type WSDL.Schema.Binding_Style;

      Key    : constant String := To_String (S.Wrapper_Name) & '.' & Name;
      Field  : DOM.Core.Node := SOAP.XML.Get_Ref (N);
      xsd    : constant String :=
                 SOAP.XML.Get_Attr_Value
                   (Field, SOAP.Name_Space.Name (S.NS.xsi) & ":type");

      --  The record fields temporary store
      OS     : Types.Object_Set (1 .. Max_Object_Size);
      K      : Natural := 0;

      T_Name : Unbounded_String; -- record's type name
      LS     : constant State := S;

   begin
      if (S.Style = WSDL.Schema.Document or else xsd = "")
        and then S.Schema.Contains (Key)
      then
         --  This should be done only for document style binding, but let's
         --  do it also for the RPC binding. It can help parsing non fully
         --  conformant messages.
         T_Name := To_Unbounded_String (S.Schema (Key));

      else
         T_Name := To_Unbounded_String (xsd);
      end if;

      if Name /= Local_Name (N)
        and then First_Child (Field).Node_Type = DOM.Core.Text_Node
      then
         --  This is not a record after all, it is an enumeration with an href
         --  A record can't have a text child node.

         return Types.E
           (Node_Value (First_Child (Field)),
            Utils.No_NS (To_String (T_Name)), Name);

      else
         Field := SOAP.XML.First_Child (Field);

         --  Set state for the enclosing elements

         S.Enclosing := To_Unbounded_String (Name);

         while Field /= null loop
            K := K + 1;
            OS (K) := +Parse_Param (Field, S);
            Field := Next_Sibling (Field);
         end loop;

         --  Restore state

         S.Enclosing := LS.Enclosing;

         declare
            NS : constant SOAP.Name_Space.Object :=
                   Get_Namespace_Object (S.NS, Utils.NS (To_String (T_Name)));
         begin
            return Types.R
              (OS (1 .. K), Name,
               Utils.No_NS (To_String (T_Name)), NS);
         end;
      end if;
   end Parse_Record;

   -----------------
   -- Parse_Short --
   -----------------

   function Parse_Short
     (Name      : String;
      Type_Name : String;
      N         : DOM.Core.Node) return Types.Object'Class
   is
      Value : constant DOM.Core.Node := First_Child (N);
   begin
      return Types.S (Types.Short'Value (Node_Value (Value)), Name, Type_Name);
   end Parse_Short;

   ------------------
   -- Parse_String --
   ------------------

   function Parse_String
     (Name      : String;
      Type_Name : String;
      N         : DOM.Core.Node) return Types.Object'Class
   is
      use type DOM.Core.Node;
      use type DOM.Core.Node_Types;

      L : constant DOM.Core.Node_List := Child_Nodes (N);
      S : Unbounded_String;
      P : DOM.Core.Node;
   begin
      for I in 0 .. Length (L) - 1 loop
         P := Item (L, I);
         if P.Node_Type = DOM.Core.Text_Node then
            Append (S, Node_Value (P));
         end if;
      end loop;

      return Types.S (S, Name, Type_Name);
   end Parse_String;

   ------------------------
   -- Parse_Time_Instant --
   ------------------------

   function Parse_Time_Instant
     (Name      : String;
      Type_Name : String;
      N         : DOM.Core.Node) return Types.Object'Class
   is
      Value : constant DOM.Core.Node := First_Child (N);
      TI    : constant String        := Node_Value (Value);
   begin
      return Utils.Time_Instant (TI, Name, Type_Name);
   end Parse_Time_Instant;

   -------------------------
   -- Parse_Unsigned_Byte --
   -------------------------

   function Parse_Unsigned_Byte
     (Name      : String;
      Type_Name : String;
      N         : DOM.Core.Node) return Types.Object'Class
   is
      Value : constant DOM.Core.Node := First_Child (N);
   begin
      return Types.UB
        (Types.Unsigned_Byte'Value (Node_Value (Value)), Name, Type_Name);
   end Parse_Unsigned_Byte;

   ------------------------
   -- Parse_Unsigned_Int --
   ------------------------

   function Parse_Unsigned_Int
     (Name      : String;
      Type_Name : String;
      N         : DOM.Core.Node) return Types.Object'Class
   is
      Value : constant DOM.Core.Node := First_Child (N);
   begin
      return Types.UI
        (Types.Unsigned_Int'Value (Node_Value (Value)), Name, Type_Name);
   end Parse_Unsigned_Int;

   -------------------------
   -- Parse_Unsigned_Long --
   -------------------------

   function Parse_Unsigned_Long
     (Name      : String;
      Type_Name : String;
      N         : DOM.Core.Node) return Types.Object'Class
   is
      Value : constant DOM.Core.Node := First_Child (N);
   begin
      return Types.UL
        (Types.Unsigned_Long'Value (Node_Value (Value)), Name, Type_Name);
   end Parse_Unsigned_Long;

   --------------------------
   -- Parse_Unsigned_Short --
   --------------------------

   function Parse_Unsigned_Short
     (Name      : String;
      Type_Name : String;
      N         : DOM.Core.Node) return Types.Object'Class
   is
      Value : constant DOM.Core.Node := First_Child (N);
   begin
      return Types.US
        (Types.Unsigned_Short'Value (Node_Value (Value)), Name, Type_Name);
   end Parse_Unsigned_Short;

   -------------------
   -- Parse_Untyped --
   -------------------

   function Parse_Untyped
     (Name : String;
      N    : DOM.Core.Node) return Types.Object'Class
   is
      use type DOM.Core.Node;
      use type DOM.Core.Node_Types;

      L : constant DOM.Core.Node_List := Child_Nodes (N);
      S : Unbounded_String;
      P : DOM.Core.Node;
   begin
      for I in 0 .. Length (L) - 1 loop
         P := Item (L, I);
         if P.Node_Type = DOM.Core.Text_Node then
            Append (S, Node_Value (P));
         end if;
      end loop;

      return Types.Untyped.S (S, Name);
   end Parse_Untyped;

   -------------------
   -- Parse_Wrapper --
   -------------------

   procedure Parse_Wrapper (N : DOM.Core.Node; S : in out State) is
      use type DOM.Core.Node_Types;
      use type SOAP.Parameters.List;

      NL     : constant DOM.Core.Node_List      := Child_Nodes (N);
      Prefix : constant String                  := DOM.Core.Nodes.Prefix (N);
      Name   : constant String                  := Local_Name (N);
      Atts   : constant DOM.Core.Named_Node_Map := Attributes (N);

   begin
      Parse_Namespaces (N, S.NS);

      if Prefix /= "" then
         --  The wrapper has a prefix

         if Length (Atts) /= 0 then
            declare
               use type DOM.Core.Node;

               xmlns : constant DOM.Core.Node :=
                         Get_Named_Item (Atts, "xmlns:" & Prefix);
            begin
               if xmlns /= null then
                  S.Name_Space :=
                    SOAP.Name_Space.Create (Prefix, Node_Value (xmlns));
               end if;
            end;

         else
            --  There is no attribute for this node, yet the wrapper is using
            --  a name space.
            S.Name_Space :=
              SOAP.Name_Space.Create
                (Prefix, Get_Namespace_Value (S.NS, Prefix));
         end if;
      end if;

      S.Wrapper_Name := To_Unbounded_String (Name);

      for K in 0 .. Length (NL) - 1 loop
         if Item (NL, K).Node_Type /= DOM.Core.Text_Node then
            S.Parameters := S.Parameters & Parse_Param (Item (NL, K), S);
         end if;
      end loop;
   end Parse_Wrapper;

   -------------
   -- To_Type --
   -------------

   function To_Type
     (Type_Name : String;
      NS        : Namespaces;
      Schema    : WSDL.Schema.Definition) return Type_State
   is

      function Is_A
        (T1_Name, T2_Name : String;
         NS               : String) return Boolean
      is (T1_Name = Utils.With_NS (NS, T2_Name)) with Inline;
      --  Returns True if T1_Name is equal to T2_Name based on namespace

      function With_Standard_NS return String;
      --  Returns Type_Name using the default name-space name to compare
      --  against the handlers name.

      ----------------------
      -- With_Standard_NS --
      ----------------------

      function With_Standard_NS return String is
         Is_Bas64 : constant Boolean :=
                      Type_Name'Length > 6
                        and then
                      Type_Name (Type_Name'Last - 6 .. Type_Name'Last)
                        = ":base64";

         XSD_NS : constant String :=
                    (if Schema.Contains (SOAP.Name_Space.XSD_URL)
                     then Schema (SOAP.Name_Space.XSD_URL)
                     else SOAP.Name_Space.Name (SOAP.Name_Space.XSD));

         ENC_NS : constant String :=
                    (if Schema.Contains (SOAP.Name_Space.SOAPENC_URL)
                     then Schema (SOAP.Name_Space.SOAPENC_URL)
                     else SOAP.Name_Space.Name (SOAP.Name_Space.SOAPENC));

         T_NS   : constant String := Utils.NS (Type_Name);
         S_NS   : constant String := (if Is_Bas64 then ENC_NS else XSD_NS);

      begin
         if T_NS = S_NS then
            return Utils.With_NS (S_NS, Type_Name);
         else
            return Type_Name;
         end if;
      end With_Standard_NS;

      T_Name : constant String :=
                 (if Schema.Contains (Type_Name)
                  then Schema (Type_Name)
                  else With_Standard_NS);

   begin
      for K in Handlers'Range loop
         if Handlers (K).Name /= null
           and then
             ((Handlers (K).Encoded
               and then Is_A (T_Name, Handlers (K).Name.all,
                              SOAP.Name_Space.Name (NS.enc)))
              or else Is_A (T_Name, Handlers (K).Name.all,
                            SOAP.Name_Space.Name (NS.xsd)))
         then
            return K;
         end if;
      end loop;

      return T_Undefined;
   end To_Type;

end SOAP.Message.XML;
