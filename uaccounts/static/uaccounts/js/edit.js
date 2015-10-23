$(function () {
    $('.nonprimary').on('mouseenter', '.address', function () {
        $(this).find('a').css('display', 'inline');
    });
    $('.nonprimary').on('mouseleave', '.address', function () {
        $(this).find('a').hide();
    });
    $('#verified').on('click', '.setprimary', function () {
        if (confirm('Set this email address as primary?')) {
            var address = $(this).parent().find('.emailaddress');
            $.ajax({
                method: 'post',
                url: primary_url,
                data: {
                    id: address.attr('name')
                },
                headers: {
                    'X-CSRFToken': Cookies.get('csrftoken')
                },
                success: function (data) {
                    if (data['success']) {
                        var old = $('#primary').text();
                        var old_id = $('#primary').attr('name');
                        $('#primary').text(address.text());
                        $('#primary').attr('name', address.attr('name'));
                        var address_p = address.parent().parent();
                        address_p.hide(200, function () {
                            address_p.remove();
                            var span = $('<span>');
                            span.attr('class', 'emailaddress');
                            span.attr('name', old_id);
                            span.text(old);
                            var del = $('<a>');
                            del.attr('href', '');
                            del.attr('class', 'action delete');
                            del.text('Delete');
                            var pri = $('<a>');
                            pri.attr('href', '');
                            pri.attr('class', 'action setprimary');
                            pri.text('Set primary');
                            var outter = $('<span>');
                            outter.attr('class', 'line');
                            outter.append(span);
                            outter.append(del);
                            outter.append(pri);
                            p = $('<p>');
                            p.attr('class', 'address hidden');
                            p.append(outter);
                            $('#verified').find(':first').after(p);
                            p.show();
                        });
                    }
                    else {
                        alert(data['error']);
                    }
                },
                error: function () {
                    alert('Could not set email address as primary');
                }
            });
        }
        return false;
    });
    $('form').on('click', '.delete', function () {
        if (confirm('Are you sure you want to delete this email address?')) {
            $.ajax({
                method: 'post',
                url: remove_url,
                data: {
                    id: $(this).parent().find('.emailaddress').attr('name')
                },
                headers: {
                    'X-CSRFToken': Cookies.get('csrftoken')
                },
                context: this,
                success: function (data) {
                    if (data['success']) {
                        var address_p = $(this).parent().parent();
                        address_p.hide(200, function () {
                            address_p.remove();
                            var verified_length = $('#verified .address').length;
                            var unverified_length = $('#unverified .address').length;
                            if (!verified_length) {
                                $('#verifiedlabel').hide(200);
                            }
                            if (!unverified_length) {
                                $('#unverifiedlabel').hide(200);
                            }
                            if (!(verified_length + unverified_length)) {
                                $('#emaillabel strong').text('Email address');
                                $('#primarylabel').hide(200);
                            }
                        });
                    }
                    else {
                        alert(data['error']);
                    }
                },
                error: function () {
                    alert('Could not delete email address');
                }
            });
        }
        return false;
    });
    $('#unverified').on('click', '.verify', function () {
        if (confirm('Send verification email to this address?')) {
            $.ajax({
                method: 'post',
                url: verify_url,
                data: {
                    id: $(this).parent().find('.emailaddress').attr('name')
                },
                headers: {
                    'X-CSRFToken': Cookies.get('csrftoken')
                },
                success: function (data) {
                    if (data['success']) {
                        alert('Verification email sent successfully');
                    }
                    else {
                        alert(data['error']);
                    }
                },
                error: function () {
                    alert('Could not send verification email');
                }
            });
        }
        return false;
    });
    $('#add').click(function () {
        var value = $('[name="newemail"]').val();
        if (value) {
            $.ajax({
                method: 'post',
                url: add_url,
                data: {
                    email: value
                },
                headers: {
                    'X-CSRFToken': Cookies.get('csrftoken')
                },
                success: function (data) {
                    if (data['success']) {
                        var span = $('<span>');
                        span.attr('class', 'emailaddress');
                        span.attr('name', data['id']);
                        span.text(value);
                        var del = $('<a>');
                        del.attr('href', '');
                        del.attr('class', 'action delete');
                        del.text('Delete');
                        var ver = $('<a>');
                        ver.attr('href', '');
                        ver.attr('class', 'action verify');
                        ver.text('Verify');
                        var outter = $('<span>');
                        outter.attr('class', 'line');
                        outter.append(span);
                        outter.append(del);
                        outter.append(ver);
                        var p = $('<p>');
                        p.attr('class', 'address hidden');
                        p.append(outter);
                        $('#unverified').append(p);
                        $('#emaillabel strong').text('Email addresses');
                        $('#primarylabel').show(200);
                        $('#unverifiedlabel').show(200);
                        p.show(200);
                        $('[name="newemail"]').val('');
                    }
                    else {
                        alert(data['error']);
                    }
                },
                error: function () {
                    alert('Could not add email address');
                }
            });
        }
        return false;
    });
    $('[name="newemail"]').keypress(function (event) {
        if (event.which == 13) {
            $('#add').click();
            return false;
        }
    });
});