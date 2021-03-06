Template.privateGroupsFlex.helpers
	selectedUsers: ->
		return Template.instance().selectedUsers.get()

	selectedUserDisplay: ->
		return Template.instance().selectedUserDisplay.get()
		
	name: ->
		return Template.instance().selectedUserNames[this.valueOf()]

	groupName: ->
		return Template.instance().groupName.get()

	error: ->
		return Template.instance().error.get()

	autocompleteSettings: ->
		return {
			limit: 10
			# inputDelay: 300
			rules: [
				{
					# @TODO maybe change this 'collection' and/or template
					collection: 'UserAndRoom'
					subscription: 'userAutocomplete'
					# Gal
					# field: 'username'
					field: 'name'
					template: Template.userSearch
					noMatchTemplate: Template.userSearchEmpty
					matchAll: true
					filter:
						# Gal 
						# exceptions: [Meteor.user().username].concat(Template.instance().selectedUsers.get())
						exceptions: [Meteor.user().username].concat(Template.instance().selectedUsers.get())
					selector: (match) ->
						return { name: match }
					sort: 'username'
				}
			]
		}

Template.privateGroupsFlex.events
	'autocompleteselect #pvt-group-members': (event, instance, doc) ->
		doc.text = doc.name
		instance.selectedUsers.set instance.selectedUsers.get().concat doc.username

		instance.selectedUserNames[doc.username] = doc.name
		
		
		instance.selectedUserDisplay.set instance.selectedUserDisplay.get().concat doc
		
		event.currentTarget.value = ''
		event.currentTarget.focus()

	'click .remove-room-member': (e, instance) ->
		self = @
		users = Template.instance().selectedUsers.get()
		allProfiles = Template.instance().selectedUserDisplay.get()
		
		users = _.reject Template.instance().selectedUsers.get(), (_id) ->
			return _id is self.valueOf().username
		
		allProfiles = _.reject Template.instance().selectedUserDisplay.get(), (_id) ->
			return _id.username is self.valueOf().username
		
		Template.instance().selectedUsers.set(users)
		Template.instance().selectedUserDisplay.set(allProfiles)

		$('#pvt-group-members').focus()

	'click .cancel-pvt-group': (e, instance) ->
		SideNav.closeFlex ->
			instance.clearForm()

	'click header': (e, instance) ->
		SideNav.closeFlex ->
			instance.clearForm()

	'mouseenter header': ->
		SideNav.overArrow()

	'mouseleave header': ->
		SideNav.leaveArrow()

	'keydown input[type="text"]': (e, instance) ->
		Template.instance().error.set([])

	'keyup #pvt-group-name': (e, instance) ->
		if e.keyCode is 13
			instance.$('#pvt-group-members').focus()

	'keydown #pvt-group-members': (e, instance) ->
		if $(e.currentTarget).val() is '' and e.keyCode is 13
			instance.$('.save-pvt-group').click()

	'click .save-pvt-group': (e, instance) ->
		err = SideNav.validate()
		name = instance.find('#pvt-group-name').value.toLowerCase().trim()
		instance.groupName.set name
		if not err
			Meteor.call 'createPrivateGroup', name, instance.selectedUsers.get(), (err, result) ->
				if err
					if err.error is 'error-invalid-name'
						instance.error.set({ invalid: true })
						return
					if err.error is 'error-duplicate-channel-name'
						instance.error.set({ duplicate: true })
						return
					if err.error is 'error-archived-duplicate-name'
						instance.error.set({ archivedduplicate: true })
						return
					return handleError(err)
				SideNav.closeFlex()
				instance.clearForm()
				FlowRouter.go 'group', { name: name }
		else
			Template.instance().error.set({fields: err})

Template.privateGroupsFlex.onCreated ->
	instance = this
	instance.selectedUsers = new ReactiveVar []
	instance.selectedUserNames = {}
	instance.selectedUserDisplay = new ReactiveVar []
	instance.error = new ReactiveVar []
	instance.groupName = new ReactiveVar ''

	instance.clearForm = ->
		instance.error.set([])
		instance.groupName.set('')
		instance.selectedUsers.set([])
		instance.selectedUserDisplay.set([])
		instance.find('#pvt-group-name').value = ''
		instance.find('#pvt-group-members').value = ''
