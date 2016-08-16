Meteor.methods
		updateRoom:	(id, name, usernames) ->
			console.log 'before if'
			console.log Meteor.userId()
			if not Meteor.userId()
				throw new Meteor.Error 'invalid-user', "[methods] updateRoom -> Invalid user"
			
			try
				nameValidation = new RegExp '^' + RocketChat.settings.get('UTF8_Names_Validation') + '$'
			catch
				nameValidation = new RegExp '^[0-9a-zA-Z-_.]+$'
				
			if not nameValidation.test name
				throw new Meteor.Error 'name-invalid'
			
			if RocketChat.authz.hasPermission(Meteor.userId(), 'edit-room') isnt true
				throw new Meteor.Error 'not-authorized', '[methods] updateRoom -> Not authorized'
			
			now = new Date()
			user = Meteor.user()
			
			oldRoom = RocketChat.models.Rooms.findOneById id
			
			if (oldRoom.name isnt name)
			
				# avoid duplicate names
				if RocketChat.models.Rooms.findOneByName name
					if RocketChat.models.Rooms.findOneByName(name).archived
						throw new Meteor.Error 'archived-duplicate-name'
					else
						throw new Meteor.Error 'duplicate-name'
					
			# name = s.slugify name
			
				room = RocketChat.models.Rooms.setNameById id, name
				RocketChat.models.Subscriptions.updateNameByRoomId id, name				
			
			# add the application user to teh users list
			usernames.push user.username
			usernames = _.map usernames, (username) ->
				username.toLowerCase(); 

			usernames = _.uniq usernames
									
			for username in usernames
				member = RocketChat.models.Users.findOneByUsername(username.toLowerCase(), { fields: { username: 1 }})
				if not member?
					temp_user = {
						name: username.toLowerCase(),
						username: username.toLowerCase(),
						email: username.toLowerCase()
					}
					
					Meteor.call 'createOrUpdateTempUser', temp_user, (error, user_id) ->
						if error
							throw new Meteor.Error 'error-create-temp-user', "Can't create a temporary user :: " + error, { method: 'updateRoom' }
					continue
			
			
			
			# RON 
			RocketChat.models.Rooms.update { _id: id }, { $set: { usernames: usernames }}
			
			return true
