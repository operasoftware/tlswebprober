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

from django.db import models

# Create your models here.


class Server(models.Model):
	full_servername = models.CharField(max_length = 330, db_index=True,unique=True)
	servername = models.CharField(max_length = 300, db_index=True)
	port = models.PositiveIntegerField()
	protocol = models.CharField(max_length = 10, db_index=True, null=True)
	alexa_rating = models.PositiveIntegerField()
	enabled = models.BooleanField()
	
	
	def __unicode__(self):
		return self.servername + ":" + str(self.port)
