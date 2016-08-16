Meteor.methods
	createPrivateGroup: (name, members) ->
		if not Meteor.userId()
			throw new Meteor.Error 'error-invalid-user', "Invalid user", { method: 'createPrivateGroup' }

		unless RocketChat.authz.hasPermission(Meteor.userId(), 'create-p')
			throw new Meteor.Error 'error-not-allowed', "Not allowed", { method: 'createPrivateGroup' }

		try
			nameValidation = new RegExp '^' + RocketChat.settings.get('UTF8_Names_Validation') + '$'
		catch
			nameValidation = new RegExp '^[0-9a-zA-Z-_.]+$'

		if not nameValidation.test name
			throw new Meteor.Error 'error-invalid-name', "Invalid name", { method: 'createPrivateGroup' }

		now = new Date()

		me = Meteor.user()

		members.push me.username

		# name = s.slugify name

		# avoid duplicate names
		if RocketChat.models.Rooms.findOneByName name
			if RocketChat.models.Rooms.findOneByName(name).archived
				throw new Meteor.Error 'error-archived-duplicate-name', "There's an archived channel with name " + name, { method: 'createPrivateGroup', room_name: name }
			else
				throw new Meteor.Error 'error-duplicate-channel-name', "A channel with name '" + name + "' exists", { method: 'createPrivateGroup', room_name: name }

		members = _.map members, (username) ->
				username.toLowerCase(); 
				
		# create new room
		room = RocketChat.models.Rooms.createWithTypeNameUserAndUsernames 'p', name, me, members,
			ts: now
			
		for username in members
			member = RocketChat.models.Users.findOneByUsername(username.toLowerCase(), { fields: { username: 1 }})
			if not member?
				temp_user = {
					name: username.toLowerCase(),
					username: username.toLowerCase(),
					email: username.toLowerCase()
				}
				
				Meteor.call 'createOrUpdateTempUser', temp_user, (error, user_id) ->
					if error
						console.log error
						throw new Meteor.Error 'error-create-temp-user', "Can't create a temporary user", { method: 'createPrivateGroup' }
					
					RocketChat.models.Subscriptions.createWithRoomAndUser room, {"_id": user_id, "username": username}, {alert: true}
				continue

			extra = {}

			if username is me.username
				extra.ls = now
			else
				extra.alert = true

			RocketChat.models.Subscriptions.createWithRoomAndUser room, member, extra

		# set creator as group moderator.  permission limited to group by scoping to rid
		RocketChat.authz.addUserRoles(Meteor.userId(), ['owner'], room._id)

		return {
			rid: room._id
		}
