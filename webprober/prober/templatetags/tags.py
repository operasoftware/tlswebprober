#   Copyright 2010-2012 Opera Software ASA 
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

from django import template

register = template.Library()

@register.inclusion_tag("color_value.html")
def color_value(collection):
	""" {% color_value collection %}
		render collection.value with the assigned color 
		depending on parameters, optionally with a link.
		
		collection.value value to be rendered 
		collection.textcolor :  The color to be used
				if callable textcolor_fun(value, collection) return the text and color based on the value as (text, color)
		collection.link: If present contain a URL to be linked to
		"""
	if not collection:
		return {"valid":False}
	
	if not isinstance(collection,dict):
		return {"valid":True, "text":collection, "color":None, "debug":collection}
	
	if not collection or "value" not in collection:
		return {"valid":False}
	
	value = collection["value"]
	color = collection.get("textcolor", None)
	
	if callable(color):
		(value, color) = color(value, collection)
	
	args = {
			"valid":True,
			"text":value, 
			"color":color,
			"debug":(value, color, collection.get("color", None), collection.get("values",None))
			}
	if "link" in collection:
		args["link"] = collection["link"];
	
	return args
	