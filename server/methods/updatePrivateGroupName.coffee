Meteor.methods
		updatePrivateGroupName:	(id, name) ->
			if not Meteor.userId()
					throw new Meteor.Error 'invalid-user', "[methods] createPrivateGroup -> Invalid user"
					
					try
						nameValidation = new RegExp '^' + RocketChat.settings.get('UTF8_Names_Validation') + '$'
					catch
						nameValidation = new RegExp '^[0-9a-zA-Z-_.]+$'
						
					if not nameValidation.test name
						throw new Meteor.Error 'name-invalid'
					
					if RocketChat.authz.hasPermission(Meteor.userId(), 'create-p') isnt true
						throw new Meteor.Error 'not-authorized', '[methods] createPrivateGroup -> Not authorized'
					
					now = new Date()
					user = Meteor.user()
					
					# avoid duplicate names
					if RocketChat.models.Rooms.findOneByName name
						if RocketChat.models.Rooms.findOneByName(name).archived
							throw new Meteor.Error 'archived-duplicate-name'
						else
							throw new Meteor.Error 'duplicate-name'
							
					# name = s.slugify name
					
					#update new Rooms
					room = RocketChat.models.Rooms.setNameById id, name
					
					return {
						rid: room._id
					}