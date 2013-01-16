#include "stdafx.h"
#include "tinyxml.h"

// ----------------------------------------------------------------------

/*
www.sourceforge.net/projects/tinyxml

This software is provided 'as-is', without any express or implied
warranty. In no event will the authors be held liable for any
damages arising from the use of this software.

Permission is granted to anyone to use this software for any
purpose, including commercial applications, and to alter it and
redistribute it freely, subject to the following restrictions:

1. The origin of this software must not be misrepresented; you must
not claim that you wrote the original software. If you use this
software in a product, an acknowledgment in the product documentation
would be appreciated but is not required.

2. Altered source versions must be plainly marked as such, and
must not be misrepresented as being the original software.

3. This notice may not be removed or altered from any source
distribution.
*/


//
//  Modified by John Manferdelli, all modifications licensed under BSD license in
//  BSDLicense.txt
//
//  Copyright (c) 2011, Intel Corporation. Some contributions 
//  Some contributions may be (c) 2011, John Manferdelli
//
//  Redistribution and use in source and binary forms, with or without 
//  modification, are permitted provided that the following conditions 
//  are met:
//    Redistributions of source code must retain the above copyright notice,
//      this list of conditions and the disclaimer below.
//    Redistributions in binary form must reproduce the above copyright
//      notice, this list of conditions and the disclaimer below in the 
//      documentation and/or other materials provided with the distribution.
//
//  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
//  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
//  TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
//  PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
//  HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
//  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
//  TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
//  PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
//  LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
//  NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
//  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//




const unsigned int NUM_INDENTS_PER_SPACE=2;

const char * getIndent( unsigned int numIndents )
{
	static const char * pINDENT="                                      + ";
	static const unsigned int LENGTH=strlen( pINDENT );
	unsigned int n=numIndents*NUM_INDENTS_PER_SPACE;
	if ( n > LENGTH ) n = LENGTH;

	return &pINDENT[ LENGTH-n ];
}

// same as getIndent but no "+" at the end
const char * getIndentAlt( unsigned int numIndents )
{
	static const char * pINDENT="                                        ";
	static const unsigned int LENGTH=strlen( pINDENT );
	unsigned int n=numIndents*NUM_INDENTS_PER_SPACE;
	if ( n > LENGTH ) n = LENGTH;

	return &pINDENT[ LENGTH-n ];
}

int dump_attribs_to_stdout(TiXmlElement* pElement, unsigned int indent)
{
	if ( !pElement ) return 0;

	TiXmlAttribute* pAttrib=pElement->FirstAttribute();
	int i=0;
	int ival;
	double dval;
	const char* pIndent=getIndent(indent);
	printf("\n");
	while (pAttrib)
	{
		printf( "%s%s: value=[%s]", pIndent, pAttrib->Name(), pAttrib->Value());

		if (pAttrib->QueryIntValue(&ival)==TIXML_SUCCESS)    printf( " int=%d", ival);
		if (pAttrib->QueryDoubleValue(&dval)==TIXML_SUCCESS) printf( " d=%1.1f", dval);
		printf( "\n" );
		i++;
		pAttrib=pAttrib->Next();
	}
	return i;	
}

void dump_to_stdout( TiXmlNode* pParent, unsigned int indent = 0 )
{
	if ( !pParent ) return;

	TiXmlNode* pChild;
	TiXmlText* pText;
	int t = pParent->Type();
	printf( "%s", getIndent(indent));
	int num;

	switch ( t )
	{
	case TiXmlNode::TINYXML_DOCUMENT:
		printf( "Document" );
		break;

	case TiXmlNode::TINYXML_ELEMENT:
		printf( "Element [%s]", pParent->Value() );
		num=dump_attribs_to_stdout(pParent->ToElement(), indent+1);
		switch(num)
		{
			case 0:  printf( " (No attributes)"); break;
			case 1:  printf( "%s1 attribute", getIndentAlt(indent)); break;
			default: printf( "%s%d attributes", getIndentAlt(indent), num); break;
		}
		break;

	case TiXmlNode::TINYXML_COMMENT:
		printf( "Comment: [%s]", pParent->Value());
		break;

	case TiXmlNode::TINYXML_UNKNOWN:
		printf( "Unknown" );
		break;

	case TiXmlNode::TINYXML_TEXT:
		pText = pParent->ToText();
		printf( "Text: [%s]", pText->Value() );
		break;

	case TiXmlNode::TINYXML_DECLARATION:
		printf( "Declaration" );
		break;
	default:
		break;
	}
	printf( "\n" );
	for ( pChild = pParent->FirstChild(); pChild != 0; pChild = pChild->NextSibling()) 
	{
		dump_to_stdout( pChild, indent+1 );
	}
}

// load the named file and dump its structure to STDOUT
void dump_to_stdout(const char* pFilename)
{
	TiXmlDocument doc(pFilename);
	bool loadOkay = doc.LoadFile();
	if (loadOkay) {
		printf("\n%s:\n", pFilename);
		dump_to_stdout( &doc ); // defined later in the tutorial
	}
	else {
		printf("Failed to load file \"%s\"\n", pFilename);
	}
}


// ----------------------------------------------------------------------


int main(int argc, char* argv[])
{
	for (int i=1; i<argc; i++) {
		dump_to_stdout(argv[i]);
	}
	return 0;
}


// ----------------------------------------------------------------------

/*
TiXmlDocument doc( "demo.xml" );
doc.LoadFile();
void write_simple_doc2( )
{
	// same as write_simple_doc1 but add each node
	// as early as possible into the tree.

	TiXmlDocument doc;
	TiXmlDeclaration * decl = new TiXmlDeclaration( "1.0", "", "" );
	doc.LinkEndChild( decl );
	
	TiXmlElement * element = new TiXmlElement( "Hello" );
	doc.LinkEndChild( element );
	
	TiXmlText * text = new TiXmlText( "World" );
	element->LinkEndChild( text );
	
	doc.SaveFile( "madeByHand2.xml" );
}

// print all attributes of pElement.
// returns the number of attributes printed
int dump_attribs_to_stdout(TiXmlElement* pElement, unsigned int indent)
{
	if ( !pElement ) return 0;

	TiXmlAttribute* pAttrib=pElement->FirstAttribute();
	int i=0;
	int ival;
	double dval;
	const char* pIndent=getIndent(indent);
	printf("\n");
	while (pAttrib)
	{
		printf( "%s%s: value=[%s]", pIndent, pAttrib->Name(), pAttrib->Value());

		if (pAttrib->QueryIntValue(&ival)==TIXML_SUCCESS)    printf( " int=%d", ival);
		if (pAttrib->QueryDoubleValue(&dval)==TIXML_SUCCESS) printf( " d=%1.1f", dval);
		printf( "\n" );
		i++;
		pAttrib=pAttrib->Next();
	}
	return i;
}

void write_app_settings_doc( )  
{  
	TiXmlDocument doc;  
	TiXmlElement* msg;
 	TiXmlDeclaration* decl = new TiXmlDeclaration( "1.0", "", "" );  
	doc.LinkEndChild( decl );  
 
	TiXmlElement * root = new TiXmlElement( "MyApp" );  
	doc.LinkEndChild( root );  

	TiXmlComment * comment = new TiXmlComment();
	comment->SetValue(" Settings for MyApp " );  
	root->LinkEndChild( comment );  
 
	TiXmlElement * msgs = new TiXmlElement( "Messages" );  
	root->LinkEndChild( msgs );  
 
	msg = new TiXmlElement( "Welcome" );  
	msg->LinkEndChild( new TiXmlText( "Welcome to MyApp" ));  
	msgs->LinkEndChild( msg );  
 
	msg = new TiXmlElement( "Farewell" );  
	msg->LinkEndChild( new TiXmlText( "Thank you for using MyApp" ));  
	msgs->LinkEndChild( msg );  
 
	TiXmlElement * windows = new TiXmlElement( "Windows" );  
	root->LinkEndChild( windows );  

	TiXmlElement * window;
	window = new TiXmlElement( "Window" );  
	windows->LinkEndChild( window );  
	window->SetAttribute("name", "MainFrame");
	window->SetAttribute("x", 5);
	window->SetAttribute("y", 15);
	window->SetAttribute("w", 400);
	window->SetAttribute("h", 250);

	TiXmlElement * cxn = new TiXmlElement( "Connection" );  
	root->LinkEndChild( cxn );  
	cxn->SetAttribute("ip", "192.168.0.1");
	cxn->SetDoubleAttribute("timeout", 123.456); // floating point attrib
	
	dump_to_stdout( &doc );
	doc.SaveFile( "appsettings.xml" );  
} 

oid AppSettings::save(const char* pFilename)
{
	TiXmlDocument doc;  
	TiXmlElement* msg;
	TiXmlComment * comment;
	string s;
 	TiXmlDeclaration* decl = new TiXmlDeclaration( "1.0", "", "" );  
	doc.LinkEndChild( decl ); 
 
	TiXmlElement * root = new TiXmlElement(m_name.c_str());  
	doc.LinkEndChild( root );  

	comment = new TiXmlComment();
	s=" Settings for "+m_name+" ";
	comment->SetValue(s.c_str());  
	root->LinkEndChild( comment );  

	// block: messages
	{
		MessageMap::iterator iter;

		TiXmlElement * msgs = new TiXmlElement( "Messages" );  
		root->LinkEndChild( msgs );  
 
		for (iter=m_messages.begin(); iter != m_messages.end(); iter++)
		{
			const string & key=(*iter).first;
			const string & value=(*iter).second;
			msg = new TiXmlElement(key.c_str());  
			msg->LinkEndChild( new TiXmlText(value.c_str()));  
			msgs->LinkEndChild( msg );  
		}
	}

	// block: windows
	{
		TiXmlElement * windowsNode = new TiXmlElement( "Windows" );  
		root->LinkEndChild( windowsNode );  

		list<WindowSettings>::iterator iter;

		for (iter=m_windows.begin(); iter != m_windows.end(); iter++)
		{
			const WindowSettings& w=*iter;

			TiXmlElement * window;
			window = new TiXmlElement( "Window" );  
			windowsNode->LinkEndChild( window );  
			window->SetAttribute("name", w.name.c_str());
			window->SetAttribute("x", w.x);
			window->SetAttribute("y", w.y);
			window->SetAttribute("w", w.w);
			window->SetAttribute("h", w.h);
		}
	}

	// block: connection
	{
		TiXmlElement * cxn = new TiXmlElement( "Connection" );  
		root->LinkEndChild( cxn );  
		cxn->SetAttribute("ip", m_connection.ip.c_str());
		cxn->SetDoubleAttribute("timeout", m_connection.timeout); 
	}

	doc.SaveFile(pFilename);  
}

void AppSettings::load(const char* pFilename)
{
	TiXmlDocument doc(pFilename);
	if (!doc.LoadFile()) return;

	TiXmlHandle hDoc(&doc);
	TiXmlElement* pElem;
	TiXmlHandle hRoot(0);

	// block: name
	{
		pElem=hDoc.FirstChildElement().Element();
		// should always have a valid root but handle gracefully if it does
		if (!pElem) return;
		m_name=pElem->Value();

		// save this for later
		hRoot=TiXmlHandle(pElem);
	}

	// block: string table
	{
		m_messages.clear(); // trash existing table

		pElem=hRoot.FirstChild( "Messages" ).FirstChild().Element();
		for( pElem; pElem; pElem=pElem->NextSiblingElement())
		{
			const char *pKey=pElem->Value();
			const char *pText=pElem->GetText();
			if (pKey && pText) 
			{
				m_messages[pKey]=pText;
			}
		}
	}

	// block: windows
	{
		m_windows.clear(); // trash existing list

		TiXmlElement* pWindowNode=hRoot.FirstChild( "Windows" ).FirstChild().Element();
		for( pWindowNode; pWindowNode; pWindowNode=pWindowNode->NextSiblingElement())
		{
			WindowSettings w;
			const char *pName=pWindowNode->Attribute("name");
			if (pName) w.name=pName;
			
			pWindowNode->QueryIntAttribute("x", &w.x); // If this fails, original value is left as-is
			pWindowNode->QueryIntAttribute("y", &w.y);
			pWindowNode->QueryIntAttribute("w", &w.w);
			pWindowNode->QueryIntAttribute("hh", &w.h);

			m_windows.push_back(w);
		}
	}

	// block: connection
	{
		pElem=hRoot.FirstChild("Connection").Element();
		if (pElem)
		{
			m_connection.ip=pElem->Attribute("ip");
			pElem->QueryDoubleAttribute("timeout",&m_connection.timeout);
		}
	}
}

 */


// ----------------------------------------------------------------------

/*
