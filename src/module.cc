/* This code is PUBLIC DOMAIN, and is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND. See the accompanying 
 * LICENSE file.
 */

#ifndef BUILDING_NODE_EXTENSION
 #define BUILDING_NODE_EXTENSION
#endif

#include <node.h>
#include <v8.h>
#include <sys/types.h>
#include <unistd.h>
#include <pwd.h>
#include "passivedns.h"


using namespace node;
using namespace v8;
