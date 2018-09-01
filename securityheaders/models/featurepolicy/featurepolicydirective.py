from securityheaders.models import Directive
from .featurepolicykeyword import FeaturePolicyKeyword

class FeaturePolicyDirective(Directive):

    ACCELEROMETER = "accelerometer"
    AMBIENT_LIGHT_SENSOR = "ambient-light-sensor",
    CAMERA = "camera"
    ENCRYPTED_MEDIA = "encrypted-media"
    FULLSCREEN = "fullscreen"
    GEOLOCATION = "geolocation"
    GYROSCOPE = "gyroscope"
    MAGNETOMETER = "magnetometer"
    MICROPHONE = "microphone"
    MIDI = "midi"
    PAYMENT = "payment"
    SPEAKER = "speaker"
    SYNC_XHR = "sync-xhr"
    USB = "usb"
    VR = "vr"
    PICTURE_IN_PICTURE = "picture-in-picture"
    DOCUMENT_WRITE = "document-write"
    IMAGE_COMPRESSION = "image-compression"
    LEGACY_IMAGE_FORMATS = "legacy-image-formats"
    MAX_DOWNSCALING_IMAGE = "max-downscaling-image"
    UNSIZED_MEDIA = "unsized-media"
    VERTICAL_SCROLL = "vertical-scroll"
    ANIMATIONS = "animations"
    AUTOPLAY = "autoplay"
    VIBRATE = 'vibrate'

    @classmethod
    def isDirective(cls, directive):
        """ Checks whether a given string is a directive

        Args:
            directive (str): the string to validate
        """
        if isinstance(directive, FeaturePolicyDirective):
            return True
        return any(directive.lower() == item.value.lower() for item in cls)


    def getDefaultValue(self):
        if self == self.PICTURE_IN_PICTURE:
            return FeaturePolicyKeyword.STAR
        return FeaturePolicyKeyword.SELF

